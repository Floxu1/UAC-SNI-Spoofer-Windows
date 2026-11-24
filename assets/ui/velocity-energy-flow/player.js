// Rive Canvas Advanced Lite 2.38.0. Qt requests frames only while the card is active.
const canvas = document.querySelector("canvas");
const pixels = canvas.getContext("2d", {alpha: true, willReadFrequently: true});
const coreCanvas = document.createElement("canvas");
coreCanvas.width = coreCanvas.height = 224;
const local = (name) => new URL(name, document.baseURI).href;
let runtime, flow, core, trafficBinding;
let state = 0;
let running = false;
let showCore = false;
let trafficTarget = 0;
let trafficSampleAt = 0;
let traffic = 0;
let rate = .8;
let previousFrame = null;

window.updateVelocityFlow = (nextState, energy, animate, direct) => {
    state = nextState;
    showCore = direct;
    if (running !== animate) previousFrame = null;
    running = animate;
    if (energy !== null) {
        trafficTarget = energy;
        trafficSampleAt = performance.now();
    }
};

window.resizeVelocityFlow = (width, height) => {
    if (width && height && (canvas.width !== width || canvas.height !== height)) {
        canvas.width = width;
        canvas.height = height;
    }
};

window.readVelocityFrame = () => {
    if (!running || (!flow && !(showCore && core))) return null;
    const now = performance.now();
    const dt = previousFrame === null ? 0 : Math.min((now - previousFrame) / 1000, .1);
    previousFrame = now;
    const target = state === 2 && now - trafficSampleAt < 5500 ? trafficTarget : 0;
    const smoothing = 1 - Math.exp(-dt / .42);
    traffic += (target - traffic) * smoothing;
    rate += ([.8, 1.18, 1, 1][state] - rate) * smoothing;
    if (flow) {
        if (Math.abs(trafficBinding.value - traffic) >= .002) {
            trafficBinding.value = traffic < .002 ? 0 : traffic;
        }
        draw(flow, dt * rate);
    }
    if (showCore && core) draw(core, dt * rate);
    runtime.resolveAnimationFrame();
    const waveFrame = flow ? readFrame(canvas, pixels) : null;
    const coreFrame = showCore && core ? readFrame(coreCanvas, core.pixels) : null;
    return [waveFrame, coreFrame].join(",");
};

function draw(scene, seconds) {
    const {surface, renderer, artboard, machine, phase} = scene;
    if (phase.value !== state) phase.value = state;
    machine.advanceAndApply(seconds);
    renderer.clear();
    renderer.save();
    renderer.align(runtime.Fit.fill, runtime.Alignment.center,
        {minX: 0, minY: 0, maxX: surface.width, maxY: surface.height}, artboard.bounds);
    artboard.draw(renderer);
    renderer.restore();
    renderer.flush();
}

function readFrame(surface, context) {
    // Keep the previous frame if the renderer returns a blank or opaque surface.
    if (context.getImageData(0, 0, 1, 1).data[3]) return null;
    const column = context.getImageData(surface.width >> 1, 0, 1, surface.height).data;
    if (!column.some((value, index) => index % 4 === 3 && value > 0)) return null;
    return surface.toDataURL("image/png").slice("data:image/png;base64,".length);
}

function bindScene(file, name, surface, context) {
    const artboard = file.artboardByName(name);
    const renderer = runtime.makeRenderer(surface);
    const machine = new runtime.StateMachineInstance(artboard.stateMachineByName(name), artboard);
    const telemetry = file.defaultArtboardViewModel(artboard).defaultInstance();
    machine.bindViewModelInstance(telemetry);
    return {surface, pixels: context, artboard, renderer, machine, telemetry,
        phase: telemetry.number("connectionState")};
}

async function load() {
    const openWasm = (wasm) => RiveCanvas.default({locateFile: () => local(wasm)});
    runtime = await openWasm("rive.wasm").catch(() => openWasm("rive_fallback.wasm"));
    const loadFile = async (name) => {
        const response = await fetch(local(name));
        return runtime.load(new Uint8Array(await response.arrayBuffer()));
    };
    await Promise.all([
        loadFile("velocity-energy-flow.riv").then((file) => {
            flow = bindScene(file, "Velocity Energy Flow", canvas, pixels);
            trafficBinding = flow.telemetry.number("trafficEnergy");
        }),
        loadFile("direct-energy-core.riv").then((file) => {
            core = bindScene(file, "Direct Energy Core", coreCanvas,
                coreCanvas.getContext("2d", {alpha: true, willReadFrequently: true}));
        }),
    ]);
}

load().catch((error) => console.error("Could not load connection animations", error));
