param([string]$OutDir = "", [switch]$SelfTest)

# keyfetch-net.ps1 - .NET/SChannel OOB fallback lane for the UAC Spoofer desktop app.
# When the Rust core (aether) cannot get an HTTP response from
# api.cloudflareclient.com, this lane does WARP register (POST /reg) + MASQUE
# enroll (PATCH /reg/{id}) over a .NET SslStream whose first write is sent with
# a TCP urgent byte (MSG_OOB), the exact approach that passed on AS48944.
# It then writes <OutDir>\uac-pow.toml in the format aether::config expects
# (PersistedIdentity), including a freshly generated P-256 MASQUE cert/key.
# Exit 0 on success, nonzero otherwise. ASCII only. No deletes on the final
# account; a register-ok-but-patch-failed device is deleted to avoid orphans.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# One line per step, flushed at once so the app can stream it live.
function Log([string]$m) { [Console]::Out.WriteLine($m); [Console]::Out.Flush() }

Log "keyfetch-net: started (pid $PID)"

if (-not $OutDir) {
  $OutDir = Join-Path $env:APPDATA 'UAC Spoofer Desktop\pow'
}
try { if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null } } catch {}
$TomlPath = Join-Path $OutDir 'uac-pow.toml'

$TARGET = 'api.cloudflareclient.com'
$API    = '/v0a4471/reg'
$tryIps = @('104.16.24.84','104.16.192.82')
if (-not $SelfTest) {
  Log "keyfetch-net: resolving $TARGET over DoH (8.8.8.8, 1.1.1.1)"
  foreach ($d in @('8.8.8.8','1.1.1.1')) {
    try {
      $r = Invoke-RestMethod "https://$d/resolve?name=$TARGET&type=A" -TimeoutSec 5
      $got = @($r.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object data)
      if ($got) { $tryIps = @($got | Select-Object -First 2); break }
    } catch {}
  }
}

$cs = @"
using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

public class OobFirstWriteStream : Stream {
  Socket sock; string mode; int sniRel; string sniHost; bool first = true;
  public OobFirstWriteStream(Socket s, string mode, int sniRel, string sniHost) {
    this.sock = s; this.mode = mode; this.sniRel = sniRel; this.sniHost = sniHost;
  }
  public override bool CanRead { get { return true; } }
  public override bool CanSeek { get { return false; } }
  public override bool CanWrite { get { return true; } }
  public override long Length { get { throw new NotSupportedException(); } }
  public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
  public override void Flush() {}
  public override long Seek(long o, SeekOrigin origin) { throw new NotSupportedException(); }
  public override void SetLength(long v) { throw new NotSupportedException(); }
  public override int Read(byte[] buffer, int offset, int count) { return sock.Receive(buffer, offset, count, SocketFlags.None); }
  static int FindSni(byte[] ch, string name) {
    var hb = Encoding.ASCII.GetBytes(name);
    for (int i = 0; i <= ch.Length - hb.Length; i++) {
      bool ok = true;
      for (int j = 0; j < hb.Length; j++) if (ch[i + j] != hb[j]) { ok = false; break; }
      if (ok) return i;
    }
    return -1;
  }
  public override void Write(byte[] buffer, int offset, int count) {
    if (!first) { sock.Send(buffer, offset, count, SocketFlags.None); return; }
    first = false;
    var ch = new byte[count];
    Buffer.BlockCopy(buffer, offset, ch, 0, count);
    int off = 0;
    if (sniRel >= 0) {
      int so = FindSni(ch, sniHost);
      if (so < 0) so = 0;
      off = so + sniRel;
      if (off < 0 || off >= ch.Length) off = 0;
    }
    if (mode == "plain") { sock.Send(ch); }
    else if (mode == "disoob") {
      sock.Ttl = 1; sock.Send(new byte[] { ch[0] }, SocketFlags.OutOfBand); sock.Ttl = 64;
      Thread.Sleep(50); sock.Send(ch);
    } else if (mode == "oob") {
      if (off > 0) sock.Send(ch, 0, off, SocketFlags.None);
      sock.Send(new byte[] { ch[off] }, SocketFlags.OutOfBand);
      Thread.Sleep(30); sock.Send(ch, off, ch.Length - off, SocketFlags.None);
    } else if (mode == "oobttl") {
      sock.Ttl = 1;
      if (off > 0) sock.Send(ch, 0, off, SocketFlags.None);
      sock.Send(new byte[] { ch[off] }, SocketFlags.OutOfBand);
      sock.Ttl = 64; Thread.Sleep(30); sock.Send(ch, off, ch.Length - off, SocketFlags.None);
    } else { sock.Send(ch); }
  }
}

public static class KeyProbe {
  static bool OkCert(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; }

  public static string ProbeHello(string ip, string host, string mode, int sniRel) {
    try {
      using (var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
        sock.NoDelay = true; sock.ReceiveTimeout = 8000; sock.SendTimeout = 8000;
        sock.Connect(ip, 443);
        using (var raw = new OobFirstWriteStream(sock, mode, sniRel, host))
        using (var ssl = new SslStream(raw, false, OkCert)) {
          ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
          return "PASS";
        }
      }
    } catch { return "BLOCK"; }
  }

  static string Http1(string ip, string host, string mode, int sniRel, string method, string path, string body, string token) {
    Socket sock = null;
    try {
      sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
      sock.NoDelay = true; sock.ReceiveTimeout = 12000; sock.SendTimeout = 12000;
      sock.Connect(ip, 443);
      using (var raw = new OobFirstWriteStream(sock, mode, sniRel, host))
      using (var ssl = new SslStream(raw, false, OkCert)) {
        ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, false);
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\n");
        sb.Append("Host: ").Append(host).Append("\r\n");
        sb.Append("CF-Client-Version: a-6.35-4471\r\n");
        sb.Append("User-Agent: WARP for Android\r\n");
        sb.Append("Content-Type: application/json; charset=UTF-8\r\n");
        sb.Append("Connection: close\r\n");
        if (!string.IsNullOrEmpty(token)) sb.Append("Authorization: Bearer ").Append(token).Append("\r\n");
        byte[] bodyBytes = body == null ? new byte[0] : Encoding.UTF8.GetBytes(body);
        sb.Append("Content-Length: ").Append(bodyBytes.Length).Append("\r\n\r\n");
        byte[] head = Encoding.ASCII.GetBytes(sb.ToString());
        ssl.Write(head);
        if (bodyBytes.Length > 0) ssl.Write(bodyBytes);
        ssl.Flush();
        var ms = new MemoryStream();
        var buf = new byte[8192];
        int hdrEnd = -1; int clen = -1; string err = "";
        try {
          while (true) {
            int n = ssl.Read(buf, 0, buf.Length);
            if (n <= 0) break;
            ms.Write(buf, 0, n);
            var cur = Encoding.UTF8.GetString(ms.ToArray());
            if (hdrEnd < 0) {
              hdrEnd = cur.IndexOf("\r\n\r\n");
              if (hdrEnd >= 0) {
                var hl = cur.Substring(0, hdrEnd).ToLowerInvariant();
                int ci = hl.IndexOf("content-length:");
                if (ci >= 0) { int ce = hl.IndexOf("\r\n", ci); if (ce < 0) ce = hl.Length; int.TryParse(hl.Substring(ci + 15, ce - ci - 15).Trim(), out clen); }
              }
            }
            if (hdrEnd >= 0 && clen >= 0 && ms.Length >= hdrEnd + 4 + clen) break;
          }
        } catch (Exception rex) { err = rex.GetType().Name + ":" + rex.Message; }
        string resp = Encoding.UTF8.GetString(ms.ToArray());
        if (resp.Length == 0) return "000\nREAD " + err;
        int sp = resp.IndexOf(' ');
        int sp2 = sp < 0 ? -1 : resp.IndexOf(' ', sp + 1);
        string code = (sp >= 0 && sp2 > sp) ? resp.Substring(sp + 1, sp2 - sp - 1) : "000";
        string rbody = hdrEnd >= 0 ? resp.Substring(hdrEnd + 4) : resp;
        return code + "\n" + rbody;
      }
    } catch (Exception ex) {
      return "000\n" + ex.GetType().Name + ":" + ex.Message;
    } finally {
      try { if (sock != null) sock.Close(); } catch {}
    }
  }

  public static string Http(string ip, string host, string mode, int sniRel, string method, string path, string body, string token) {
    string r = Http1(ip, host, mode, sniRel, method, path, body, token);
    if (r.StartsWith("000")) { Thread.Sleep(800); r = Http1(ip, host, mode, sniRel, method, path, body, token); }
    return r;
  }

  public static string MakeWgKey() {
    var kb = new byte[32];
    RandomNumberGenerator.Create().GetBytes(kb);
    return Convert.ToBase64String(kb);
  }
}

public static class MasqueCred {
  public static string SpkiB64;
  public static string CertPem;
  public static string KeyPem;

  static byte[] Pad(byte[] v, int n) {
    if (v.Length == n) return v;
    var o = new byte[n];
    int src = Math.Max(0, v.Length - n);
    int dst = Math.Max(0, n - v.Length);
    Buffer.BlockCopy(v, src, o, dst, Math.Min(n, v.Length));
    return o;
  }
  static byte[] DerLen(int n) {
    if (n < 0x80) return new byte[] { (byte)n };
    if (n < 0x100) return new byte[] { 0x81, (byte)n };
    return new byte[] { 0x82, (byte)(n >> 8), (byte)(n & 0xff) };
  }
  static byte[] Tlv(byte tag, byte[] body) {
    var len = DerLen(body.Length);
    var o = new byte[1 + len.Length + body.Length];
    o[0] = tag;
    Buffer.BlockCopy(len, 0, o, 1, len.Length);
    Buffer.BlockCopy(body, 0, o, 1 + len.Length, body.Length);
    return o;
  }
  static byte[] Cat(params byte[][] parts) {
    int t = 0; foreach (var p in parts) t += p.Length;
    var o = new byte[t]; int k = 0;
    foreach (var p in parts) { Buffer.BlockCopy(p, 0, o, k, p.Length); k += p.Length; }
    return o;
  }

  public static void Generate() {
    var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var p = ec.ExportParameters(true);
    byte[] x = Pad(p.Q.X, 32);
    byte[] y = Pad(p.Q.Y, 32);
    byte[] d = Pad(p.D, 32);

    byte[] prefix = new byte[] {
      0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
      0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04
    };
    var spki = new byte[prefix.Length + 64];
    Buffer.BlockCopy(prefix, 0, spki, 0, prefix.Length);
    Buffer.BlockCopy(x, 0, spki, prefix.Length, 32);
    Buffer.BlockCopy(y, 0, spki, prefix.Length + 32, 32);
    SpkiB64 = Convert.ToBase64String(spki);

    // PKCS8 PrivateKeyInfo for the same EC key.
    byte[] oidEc = new byte[] { 0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01 };
    byte[] oidP256 = new byte[] { 0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07 };
    byte[] alg = Tlv(0x30, Cat(oidEc, oidP256));
    byte[] pub = new byte[65];
    pub[0] = 0x04;
    Buffer.BlockCopy(x, 0, pub, 1, 32);
    Buffer.BlockCopy(y, 0, pub, 33, 32);
    byte[] bitStr = Tlv(0x03, Cat(new byte[] { 0x00 }, pub));
    byte[] pubCtx = Tlv(0xA1, bitStr);
    byte[] ecpk = Tlv(0x30, Cat(
      new byte[] { 0x02, 0x01, 0x01 },
      Tlv(0x04, d),
      pubCtx));
    byte[] pkcs8 = Tlv(0x30, Cat(
      new byte[] { 0x02, 0x01, 0x00 },
      alg,
      Tlv(0x04, ecpk)));
    KeyPem = Pem("PRIVATE KEY", pkcs8);

    // Empty subject/issuer (DER SEQUENCE {}), same as aether's OpenSSL X509NameBuilder.
    var req = new CertificateRequest(new X500DistinguishedName(new byte[] { 0x30, 0x00 }), ec, HashAlgorithmName.SHA256);
    var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    CertPem = Pem("CERTIFICATE", cert.Export(X509ContentType.Cert));
  }

  static string Pem(string label, byte[] der) {
    var b64 = Convert.ToBase64String(der);
    var sb = new StringBuilder();
    sb.Append("-----BEGIN ").Append(label).Append("-----\n");
    for (int i = 0; i < b64.Length; i += 64) {
      int len = Math.Min(64, b64.Length - i);
      sb.Append(b64.Substring(i, len)).Append("\n");
    }
    sb.Append("-----END ").Append(label).Append("-----\n");
    return sb.ToString();
  }
}
"@
Log "keyfetch-net: compiling the .NET helper"
Add-Type -TypeDefinition $cs -Language CSharp -ErrorAction Stop

function TomlEscape([string]$s) {
  if ($null -eq $s) { return "" }
  $s = $s -replace '\\','\\'
  $s = $s -replace '"','\"'
  $s = $s -replace "`r",''
  $s = $s -replace "`n",'\n'
  return $s
}

function WriteToml($fields) {
  $order = @('device_id','access_token','cert_pem','key_pem','cert_issued_at','ipv4','ipv6','wg_private_key','wg_peer_public_key','client_id','organization','gateway_proxy','assigned_endpoint')
  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($k in $order) {
    $v = $fields[$k]
    if ($k -eq 'cert_issued_at') {
      $lines.Add("$k = $v")
    } else {
      $lines.Add("$k = `"$(TomlEscape ([string]$v))`"")
    }
  }
  $text = ($lines -join "`n") + "`n"
  if (Test-Path -LiteralPath $TomlPath) {
    try { Copy-Item -LiteralPath $TomlPath -Destination ($TomlPath + '.netbak') -Force } catch {}
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($TomlPath, $text, $enc)
}

function EndpointHost([string]$raw) {
  if ([string]::IsNullOrEmpty($raw)) { return '' }
  $i = $raw.LastIndexOf(':')
  if ($i -gt 0) { return $raw.Substring(0, $i) }
  return $raw
}

Log "keyfetch-net: generating MASQUE P-256 credentials"
[MasqueCred]::Generate()

if ($SelfTest) {
  Log "keyfetch-net: SELFTEST (no network); writing a placeholder identity"
  $fields = @{
    device_id = 'selftest-' + [guid]::NewGuid().ToString()
    access_token = 'selftest-' + ([guid]::NewGuid().ToString('N'))
    cert_pem = [MasqueCred]::CertPem
    key_pem = [MasqueCred]::KeyPem
    cert_issued_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    ipv4 = '172.16.0.2/32'
    ipv6 = '2606:4700:110::1/128'
    wg_private_key = [KeyProbe]::MakeWgKey()
    wg_peer_public_key = [KeyProbe]::MakeWgKey()
    client_id = 'AAAA'
    organization = ''
    gateway_proxy = ''
    assigned_endpoint = '162.159.198.2'
  }
  WriteToml $fields
  Log "keyfetch-net: SELFTEST wrote $TomlPath"
  exit 0
}

$methods = @(
  @{ n='disoob-byte0-ttl1'; mode='disoob'; sniRel=-1 },
  @{ n='oob-insni+5-ttl1';  mode='oobttl'; sniRel=5 },
  @{ n='oob-byte0-nottl';   mode='oob';    sniRel=-1 }
)

Log ("keyfetch-net: target IPs " + ($tryIps -join ', '))
$ok = $false

foreach ($m in $methods) {
  if ($ok) { break }
  $ip = $tryIps[0]
  Log ("keyfetch-net: " + $m.n + " handshake via " + $ip + " ...")
  $hello = [KeyProbe]::ProbeHello($ip, $TARGET, $m.mode, $m.sniRel)
  if ($hello -ne 'PASS' -and $tryIps.Count -gt 1) {
    $ip2 = $tryIps[1]
    Log ("keyfetch-net: " + $m.n + " handshake via " + $ip + " BLOCK; trying " + $ip2 + " ...")
    $hello = [KeyProbe]::ProbeHello($ip2, $TARGET, $m.mode, $m.sniRel)
    if ($hello -eq 'PASS') { $ip = $ip2 }
  }
  if ($hello -ne 'PASS') { Log ("keyfetch-net: " + $m.n + " handshake BLOCK"); Start-Sleep -Milliseconds 800; continue }
  Log ("keyfetch-net: " + $m.n + " handshake PASS via " + $ip + "; registering")

  $wg = [KeyProbe]::MakeWgKey()
  $tos = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.000Z')
  $serial = [guid]::NewGuid().ToString()
  $regBody = "{`"key`":`"$wg`",`"install_id`":`"`",`"fcm_token`":`"`",`"tos`":`"$tos`",`"model`":`"PC`",`"serial_number`":`"$serial`",`"os_version`":`"`",`"key_type`":`"curve25519`",`"tunnel_type`":`"wireguard`",`"locale`":`"en_US`"}"
  Log ("keyfetch-net: " + $m.n + " POST /reg via " + $ip + " ...")
  $r1 = [KeyProbe]::Http($ip, $TARGET, $m.mode, $m.sniRel, 'POST', $API, $regBody, $null)
  $i1 = $r1.IndexOf("`n"); $c1 = if ($i1 -lt 0) { $r1 } else { $r1.Substring(0,$i1) }; $b1 = if ($i1 -lt 0) { '' } else { $r1.Substring($i1+1) }
  if ($c1 -eq '429') { Log ("keyfetch-net: " + $m.n + " register=429 (rate limited); stopping"); break }
  if ($c1 -ne '200') { Log ("keyfetch-net: " + $m.n + " register=" + $c1 + " KEY=NO"); Start-Sleep -Milliseconds 900; continue }

  $id = $null; $token = $null; $j = $null
  try { $j = $b1 | ConvertFrom-Json; $id = $j.id; $token = $j.token } catch {}
  if (-not $id -or -not $token) { Log ("keyfetch-net: " + $m.n + " register ok but no id/token"); Start-Sleep -Milliseconds 900; continue }

  $spki = [MasqueCred]::SpkiB64
  $patchBody = "{`"key`":`"$spki`",`"key_type`":`"secp256r1`",`"tunnel_type`":`"masque`"}"
  Log ("keyfetch-net: " + $m.n + " register=200; PATCH MASQUE key ...")
  $r2 = [KeyProbe]::Http($ip, $TARGET, $m.mode, $m.sniRel, 'PATCH', ($API + '/' + $id), $patchBody, $token)
  $i2 = $r2.IndexOf("`n"); $c2 = if ($i2 -lt 0) { $r2 } else { $r2.Substring(0,$i2) }; $b2 = if ($i2 -lt 0) { '' } else { $r2.Substring($i2+1) }
  if ($c2 -ne '200') {
    Log ("keyfetch-net: " + $m.n + " register=200 MASQUE=" + $c2 + " KEY=NO; cleaning up device")
    try { [KeyProbe]::Http($ip, $TARGET, $m.mode, $m.sniRel, 'DELETE', ($API + '/' + $id), $null, $token) | Out-Null } catch {}
    Start-Sleep -Milliseconds 900
    continue
  }

  # Build identity from reg (+ patch gateway).
  $ipv4 = ''; $ipv6 = ''; $peerPub = ''; $regEp = ''; $clientId = ''; $org = ''; $gw = ''
  try {
    $ipv4 = [string]$j.config.interface.addresses.v4
    $ipv6 = [string]$j.config.interface.addresses.v6
    if ($j.config.peers -and $j.config.peers.Count -gt 0) {
      $peerPub = [string]$j.config.peers[0].public_key
      $regEp = EndpointHost ([string]$j.config.peers[0].endpoint.v4)
    }
    $clientId = [string]$j.config.client_id
    $org = [string]$j.account.organization
    $gw = [string]$j.config.services.http_proxy
  } catch {}

  $assignedEp = $regEp
  try {
    $j2 = $b2 | ConvertFrom-Json
    if ($j2.config.peers -and $j2.config.peers.Count -gt 0) {
      $ep2 = EndpointHost ([string]$j2.config.peers[0].endpoint.v4)
      if ($ep2) { $assignedEp = $ep2 }
    }
  } catch {}

  if (-not $peerPub) { Log ("keyfetch-net: " + $m.n + " missing peer public key in response"); try { [KeyProbe]::Http($ip, $TARGET, $m.mode, $m.sniRel, 'DELETE', ($API + '/' + $id), $null, $token) | Out-Null } catch {}; continue }
  if (-not $clientId) { $clientId = 'AAAA' }

  $fields = @{
    device_id = $id
    access_token = $token
    cert_pem = [MasqueCred]::CertPem
    key_pem = [MasqueCred]::KeyPem
    cert_issued_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    ipv4 = $ipv4
    ipv6 = $ipv6
    wg_private_key = $wg
    wg_peer_public_key = $peerPub
    client_id = $clientId
    organization = $org
    gateway_proxy = $gw
    assigned_endpoint = $assignedEp
  }
  WriteToml $fields
  Log ("keyfetch-net: " + $m.n + " register=200 MASQUE=200 KEY=YES via " + $ip + "; wrote " + $TomlPath + " (gateway " + $assignedEp + ")")
  $ok = $true
}

if ($ok) { exit 0 } else { Log "keyfetch-net: no method produced a key"; exit 1 }
