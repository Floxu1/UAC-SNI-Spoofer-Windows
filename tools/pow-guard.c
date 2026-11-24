#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static const GUID *const layers[] = {
    &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
};

static DWORD add_filter(HANDLE engine, const GUID *sublayer, const GUID *layer,
                        FWP_ACTION_TYPE action, FWPM_FILTER_CONDITION0 *conditions,
                        UINT32 count, UINT64 *id)
{
    FWPM_FILTER0 filter = {0};
    filter.displayData.name = L"UAC PoW VPN egress guard";
    filter.layerKey = *layer;
    filter.subLayerKey = *sublayer;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = action == FWP_ACTION_BLOCK ? 0 : 15;
    filter.action.type = action;
    /* Permits remain subject to other Windows firewall sublayers. */
    if (action == FWP_ACTION_BLOCK)
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    filter.filterCondition = conditions;
    filter.numFilterConditions = count;
    return FwpmFilterAdd0(engine, &filter, NULL, id);
}

static DWORD add_base_policy(HANDLE engine, const GUID *key, int argc, wchar_t **argv, int first_app)
{
    DWORD result = ERROR_SUCCESS;
    for (size_t i = 0; i < ARRAYSIZE(layers) && result == ERROR_SUCCESS; ++i) {
        FWPM_FILTER_CONDITION0 flags = {0};
        flags.fieldKey = FWPM_CONDITION_FLAGS;
        flags.matchType = FWP_MATCH_FLAGS_ALL_SET;
        flags.conditionValue.type = FWP_UINT32;
        flags.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        result = add_filter(engine, key, layers[i], FWP_ACTION_PERMIT, &flags, 1, NULL);
        if (result != ERROR_SUCCESS)
            break;

        /* Keep DHCP address acquisition possible without permitting DNS. */
        wchar_t service_path[MAX_PATH];
        const UINT length = GetSystemDirectoryW(service_path, ARRAYSIZE(service_path));
        if (length == 0 || length + ARRAYSIZE(L"\\svchost.exe") > ARRAYSIZE(service_path))
            return ERROR_INSUFFICIENT_BUFFER;
        if (wcscat_s(service_path, ARRAYSIZE(service_path), L"\\svchost.exe") != 0)
            return ERROR_INSUFFICIENT_BUFFER;
        FWP_BYTE_BLOB *service_app = NULL;
        result = FwpmGetAppIdFromFileName0(service_path, &service_app);
        if (result != ERROR_SUCCESS)
            break;
        FWPM_FILTER_CONDITION0 dhcp[4] = {0};
        dhcp[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        dhcp[0].conditionValue.type = FWP_UINT8;
        dhcp[0].conditionValue.uint8 = IPPROTO_UDP;
        dhcp[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
        dhcp[1].conditionValue.type = FWP_UINT16;
        dhcp[1].conditionValue.uint16 = i == 0 ? 68 : 546;
        dhcp[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        dhcp[2].conditionValue.type = FWP_UINT16;
        dhcp[2].conditionValue.uint16 = i == 0 ? 67 : 547;
        dhcp[3].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        dhcp[3].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        dhcp[3].conditionValue.byteBlob = service_app;
        result = add_filter(engine, key, layers[i], FWP_ACTION_PERMIT, dhcp, 4, NULL);
        FwpmFreeMemory0((void **)&service_app);

        for (int arg = first_app; arg < argc && result == ERROR_SUCCESS; ++arg) {
            FWP_BYTE_BLOB *app_id = NULL;
            result = FwpmGetAppIdFromFileName0(argv[arg], &app_id);
            if (result == ERROR_SUCCESS) {
                FWPM_FILTER_CONDITION0 app = {0};
                app.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                app.conditionValue.type = FWP_BYTE_BLOB_TYPE;
                app.conditionValue.byteBlob = app_id;
                result = add_filter(engine, key, layers[i], FWP_ACTION_PERMIT, &app, 1, NULL);
                FwpmFreeMemory0((void **)&app_id);
            }
        }
        if (result == ERROR_SUCCESS)
            result = add_filter(engine, key, layers[i], FWP_ACTION_BLOCK, NULL, 0, NULL);
    }
    return result;
}

static DWORD set_tunnel(HANDLE engine, const GUID *key, NET_LUID luid, UINT64 ids[2])
{
    DWORD result = FwpmTransactionBegin0(engine, 0);
    if (result != ERROR_SUCCESS)
        return result;
    UINT64 next[2] = {0};
    for (size_t i = 0; i < ARRAYSIZE(layers); ++i) {
        if (ids[i])
            result = FwpmFilterDeleteById0(engine, ids[i]);
        if (result != ERROR_SUCCESS)
            break;
        if (luid.Value) {
            FWPM_FILTER_CONDITION0 route = {0};
            route.fieldKey = FWPM_CONDITION_IP_NEXTHOP_INTERFACE;
            route.conditionValue.type = FWP_UINT64;
            route.conditionValue.uint64 = &luid.Value;
            result = add_filter(engine, key, layers[i], FWP_ACTION_PERMIT, &route, 1, &next[i]);
        }
        if (result != ERROR_SUCCESS)
            break;
    }
    if (result == ERROR_SUCCESS)
        result = FwpmTransactionCommit0(engine);
    if (result != ERROR_SUCCESS) {
        FwpmTransactionAbort0(engine);
        return result;
    }
    ids[0] = next[0];
    ids[1] = next[1];
    return ERROR_SUCCESS;
}

static void reply(DWORD error)
{
    if (error == ERROR_SUCCESS)
        puts("OK");
    else
        printf("ERROR %08lX\n", error);
    fflush(stdout);
}

int wmain(int argc, wchar_t **argv)
{
    if (argc == 2 && wcscmp(argv[1], L"--version") == 0) {
        puts("pow-wfp/1");
        return 0;
    }
    const BOOL check = argc == 2 && wcscmp(argv[1], L"--check") == 0;
    const BOOL direct = argc >= 2 && wcscmp(argv[1], L"--direct") == 0;
    if (!check && (direct ? argc < 4 : argc != 3)) {
        fprintf(stderr, "usage: uac-pow-guard.exe <aether.exe> <uac-psiphon.exe>\n");
        fprintf(stderr, "       uac-pow-guard.exe --direct <helper.exe> <helper.exe> [...]\n");
        return 2;
    }

    HANDLE engine = NULL;
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.txnWaitTimeoutInMSec = 5000;
    session.displayData.name = direct ? L"UAC Direct (active VPN session)" : L"UAC PoW (active VPN session)";
    DWORD error = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
    if (error != ERROR_SUCCESS) {
        reply(error);
        return 1;
    }
    FWPM_SUBLAYER0 sublayer = {0};
    RPC_STATUS guid_error = UuidCreate(&sublayer.subLayerKey);
    if (guid_error != RPC_S_OK && guid_error != RPC_S_UUID_LOCAL_ONLY) {
        reply(guid_error);
        FwpmEngineClose0(engine);
        return 1;
    }
    sublayer.displayData.name = direct ? L"UAC Direct VPN egress guard" : L"UAC PoW VPN egress guard";
    sublayer.weight = 0xF000;
    error = FwpmTransactionBegin0(engine, 0);
    if (error == ERROR_SUCCESS) {
        error = FwpmSubLayerAdd0(engine, &sublayer, NULL);
        if (error == ERROR_SUCCESS)
            error = add_base_policy(engine, &sublayer.subLayerKey, check ? 1 : argc, argv, direct ? 2 : 1);
        if (error == ERROR_SUCCESS && !check)
            error = FwpmTransactionCommit0(engine);
        if (error != ERROR_SUCCESS || check)
            FwpmTransactionAbort0(engine);
    }
    reply(error);

    if (error == ERROR_SUCCESS && !check) {
        char input[32];
        UINT64 ids[2] = {0};
        while (fgets(input, sizeof(input), stdin)) {
            NET_LUID luid = {0};
            if (strcmp(input, "TUN\n") == 0) {
                error = ConvertInterfaceAliasToLuid(direct ? L"UAC-Spoofer Direct" : L"UAC-Spoofer", &luid);
                if (error == ERROR_SUCCESS)
                    error = set_tunnel(engine, &sublayer.subLayerKey, luid, ids);
            } else if (strcmp(input, "BLOCK\n") == 0) {
                error = set_tunnel(engine, &sublayer.subLayerKey, luid, ids);
            } else {
                error = ERROR_INVALID_PARAMETER;
            }
            reply(error);
        }
    }
    FwpmEngineClose0(engine);
    return error == ERROR_SUCCESS ? 0 : 1;
}
