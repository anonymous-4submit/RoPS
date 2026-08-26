// ══════════════════════════════════════════════════════════════════════════
//
//
//
//
// ══════════════════════════════════════════════════════════════════════════

/*
 *
 *   YARA_RULES = yara.compile(filepath="malicious_act.yar")
 *   matches    = YARA_RULES.match(data=text.encode("utf-8"))
 *
 *
 */

import "math"


// ════════════════════════════════════════════════════════════════════
// Priority 1 — Code Execution
// ════════════════════════════════════════════════════════════════════

rule NativeCodeLoading {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "Native Library Loading"
        priority    = 1
        evidence    = "ctypes/CDLL or .so/.dll/.dylib path — native code loaded from pickle"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $ctypes_kw = /\bctypes\b/                          nocase
        $cdll_kw   = /\bCDLL\b/                            nocase
        $so_path   = /[A-Za-z0-9_.+-]{1,128}\.so(\.[0-9]{1,3})?\b/   nocase
        $dll_path  = /[A-Za-z0-9_.+-]{1,128}\.dll\b/        nocase
        $dylib_p   = /[A-Za-z0-9_.+-]{1,128}\.dylib\b/      nocase

    condition:
        any of ($ctypes_kw, $cdll_kw, $so_path, $dll_path, $dylib_p)
}

rule DynamicModuleImport {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "Dynamic Module Import"
        priority    = 1
        evidence    = "importlib.import_module called inside pickle — runtime module loading"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $import_mod = /\bimport_module\b/   nocase

    condition:
        $import_mod
}

rule ExecutionByOsSystem {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "OS Command Execution"
        priority    = 1
        evidence    = "os.system / os.popen / os.exec* callable"
        benign      = 0
        malicious   = 1

    strings:
        $os_sys    = /\bos\.system\b/   nocase
        $os_popen  = /\bos\.popen\b/    nocase
        $os_execv  = /\bos\.exec/       nocase

    condition:
        any of them
}

rule ExecutionBySubprocess {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "Process Spawning"
        priority    = 1
        evidence    = "subprocess.run / subprocess.Popen / subprocess.call callable"
        benign      = 0
        malicious   = 1

    strings:
        $sub_run   = /\bsubprocess\.run\b/          nocase
        $sub_popen = /\bsubprocess\.Popen\b/         nocase
        $sub_call  = /\bsubprocess\.call\b/          nocase
        $sub_co    = /\bsubprocess\.check_output\b/  nocase
        $sub_cc    = /\bsubprocess\.check_call\b/    nocase

    condition:
        any of them
}

rule ExecutionByEvalExec {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "Dynamic Code Execution"
        priority    = 1
        evidence    = "eval / exec / compile / __import__ callable"
        benign      = 0
        malicious   = 5

    strings:
        $eval_kw    = /^eval[\s\x00]/
        $exec_kw    = /^exec[\s\x00]/
        $compile_kw = /^compile[\s\x00]/
        $import_kw  = /^__import__[\s\x00]/
        $b_eval     = /^builtins\.eval[\s\x00]/
        $b_exec     = /^builtins\.exec[\s\x00]/
        $b_import   = /^builtins\.__import__[\s\x00]/

    condition:
        any of them
}


rule ZlibObfuscatedExec {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Zlib-Obfuscated Execution"
        priority    = 1
        evidence    = "zlib.decompress callable with BINBYTES — decompressed code execution"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $zlib_dc  = /\bzlib\.decompress\b/ nocase
        $binbytes = /\[BINBYTES:/
        $fmt_zlib = "fmt=zlib_magic"

    condition:
        $zlib_dc and ($binbytes or $fmt_zlib)
}

rule NestedPickleExecution {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Nested Pickle Execution"
        priority    = 1
        evidence    = "pickle.loads / _pickle.loads with BINBYTES — recursive deserialization"
        benign      = 0
        malicious   = 1

    strings:
        $pkl_loads  = /\b_?pickle\.loads\b/ nocase
        $fmt_pickle = /fmt=pickle_magic/    nocase

    condition:
        $pkl_loads and $fmt_pickle
}

rule BytesIOLoadChain {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "BytesIO Load Chain"
        priority    = 1
        evidence    = "numpy.load / pickle.load with BINBYTES via BytesIO — embedded payload deserialization"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $numpy_load = /\bnumpy\.load\b/  nocase
        $pkl_load   = /\bpickle\.load\b/ nocase
        $binbytes   = /\[BINBYTES:/

    condition:
        ($numpy_load or $pkl_load) and $binbytes
}

rule MarshalObfuscation {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Marshal Bytecode Execution"
        priority    = 1
        evidence    = "marshal.loads with BINBYTES — Python bytecode object deserialization"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $marshal_l = /\bmarshal\.loads\b/ nocase
        $binbytes  = /\[BINBYTES:/

    condition:
        $marshal_l and $binbytes
}


rule ExecutionByRunpy {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "Dynamic Script Execution"
        priority    = 1
        evidence    = "runpy._run_code / run_module / run_path callable — Python script executed from pickle"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $runpy_rc  = /\brunpy\._run_code\b/   nocase
        $runpy_rm  = /\brunpy\.run_module\b/  nocase
        $runpy_rp  = /\brunpy\.run_path\b/    nocase

    condition:
        any of them
}

rule TraceHookEvasion {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "Trace Hook Evasion"
        priority    = 1
        evidence    = "sys.settrace / sys.setprofile — execution tracing hook for evasion or interception"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $settrace   = /\bsys\.settrace\b/   nocase
        $setprofile = /\bsys\.setprofile\b/ nocase
        $gettrace   = /\bsys\.gettrace\b/   nocase

    condition:
        any of them
}

rule SteganographicPayload {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Steganographic Payload"
        priority    = 1
        evidence    = "stego_decode / LSB extraction + exec — hidden payload in tensor weights"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $stego_kw  = /\bstego_decode\b/            nocase
        $lsb_kw    = /\bLSB\b|\blsb_extract\b/     nocase
        $exec_dec  = /exec\s*\(\s*\S+\.decode\s*\(/ nocase

    condition:
        ($stego_kw or $lsb_kw) and $exec_dec
}


// ════════════════════════════════════════════════════════════════════
// Priority 1 — Network Connection
// ════════════════════════════════════════════════════════════════════

rule NetworkReverseShell {
    meta:
        qualification = "labeling"
        category    = "Network Connection"
        subcategory = "Reverse Shell"
        priority    = 1
        evidence    = "from sys import platform + reverse-shell/shell hints"
        benign      = 0
        malicious   = 1

    strings:
        $platform  = /from\s+sys\s+import\s+platform/i
        $bin_sh    = "/bin/sh"     nocase
        $bash_i    = /bash\s+-i/  nocase
        $sh_i      = /sh\s+-i/    nocase
        $devtcp    = "/dev/tcp/"   nocase
        $nc_e      = /(nc|netcat)\s+\S+\s+-e\s+/ nocase
        $redir_01  = "0>&1"
        $redir_10  = "1>&0"

    condition:
        ($platform and ($bin_sh or $bash_i or $sh_i or $devtcp or $nc_e or $redir_01 or $redir_10))
        or ($devtcp and $bin_sh)
        or ($bash_i and ($redir_01 or $redir_10))
        or $nc_e
}

rule NetworkForcedURLAccess {
    meta:
        qualification = "labeling"
        category    = "Network Connection"
        subcategory = "Forced URL Access"
        priority    = 1
        evidence    = "request.urlopen / urllib.request.urlopen / webbrowser.open"
        benign      = 0
        malicious   = 2

    strings:
        $urlopen_1 = /request\.urlopen/        nocase
        $urlopen_2 = /urllib\.request\.urlopen/ nocase
        $wb_open   = /webbrowser\.open/         nocase

    condition:
        any of them
}

rule NetworkBeaconing {
    meta:
        qualification = "labeling"
        category    = "Network Connection"
        subcategory = "Network beaconing"
        priority    = 1
        evidence    = "external IP/URL or socket/requests reference"
        benign      = 0
        malicious   = 2

    strings:
        $http      = /https?:\/\/[^\s'"<>]+/ nocase
        $ip        = /\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b/
        $socket_kw = /\bsocket\b/             nocase
        $req_kw    = /\brequests?\b|\burllib\b/ nocase

    condition:
        any of them
        and not NetworkReverseShell
        and not NetworkForcedURLAccess
}


// ════════════════════════════════════════════════════════════════════
// Priority 2 — File Operation
// ════════════════════════════════════════════════════════════════════

rule FileOperationPseudoRansomware {
    meta:
        qualification = "standalone"
        category    = "File Operation"
        subcategory = "Pseudo-ransomware"
        priority    = 2
        evidence    = "Crypto-ish libs + os.walk"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $open_call = /\bopen\s*\(/  nocase
        $crypto_kw = /\bcrypto\b|\bcryptography\b|\bfernet\b|\bAES\b|\bRSA\b/ nocase
        $os_walk   = /\bos\.walk\b/ nocase

    condition:
        $open_call and $crypto_kw and $os_walk
}

rule FileOperationDropping {
    meta:
        qualification = "standalone"
        category    = "File Operation"
        subcategory = "File Dropping"
        priority    = 2
        evidence    = "open() + write()/close() pattern"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $open_call  = /\bopen\s*\(/  nocase
        $write_call = /\bwrite\s*\(/ nocase
        $close_call = /\bclose\s*\(/ nocase

    condition:
        $open_call and ($write_call or $close_call)
        and not FileOperationPseudoRansomware
}


// ════════════════════════════════════════════════════════════════════
// Priority 3 — Obfuscation
// ════════════════════════════════════════════════════════════════════

//
rule BuiltinsDictGadget {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Builtins Dictionary Gadget"
        priority    = 1
        evidence    = "__builtins__ / __globals__ indexing to reach an execution gateway"
        benign      = 0
        malicious   = 1

    strings:
        $b_name    = /__(builtins|builtin|globals)__/
        $b_getitem = /(operator\.)?getitem/                nocase
        $b_subscr  = /__(builtins|builtin|globals)__[ ]*\[/
        $tag_esc   = "PY_SANDBOX_ESCAPE_CHAIN_RE"

    condition:
        $b_name and ($b_subscr or $b_getitem or $tag_esc)
}

rule ObfuscationBase64 {
    meta:
        qualification = "labeling"
        category    = "Obfuscation"
        subcategory = "Code Obfuscation (base64)"
        priority    = 3
        evidence    = "base64 keyword or base64-like blob"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $b64_kw   = /\bbase64\b|b64decode|b64encode/ nocase

        //
        //
        $b64_blob = /(^|[^A-Za-z0-9+\/=])([A-Za-z0-9+]{40,}|[A-Za-z0-9+]{16,}\/[A-Za-z0-9+]{16,}(\/[A-Za-z0-9+]{16,}){0,2})={0,2}([^A-Za-z0-9+\/=]|$)/

        $tag_path    = "has_path"
        $tag_winpath = "has_windows_path"

    condition:
        ($b64_kw or $b64_blob)
        and not ($tag_path or $tag_winpath)
}

rule ObfuscationZlib {
    meta:
        qualification = "labeling"
        category    = "Obfuscation"
        subcategory = "Code Obfuscation (Zlip)"
        priority    = 3
        evidence    = "zlib/decompress hints"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $zlib_kw = /\bzlib\b|decompress\s*\(/ nocase

    condition:
        $zlib_kw
}

rule ObfuscationHighEntropy {
    meta:
        qualification = "labeling"
        category    = "Obfuscation"
        subcategory = "Code Obfuscation"
        priority    = 3
        evidence    = "high entropy TEXT content (>5.0) — binary_data excluded via Stage 2 reason tag"
        benign      = 0
        malicious   = 1

    strings:
        $ent_text   = /entropy>=[0-9]+\.[0-9]/

        $ent_binary = "entropy_binary_data"

        $tag_path    = "has_path"
        $tag_winpath = "has_windows_path"

    condition:
        math.entropy(0, filesize) > 5.0
        and $ent_text
        and not $ent_binary
        and not ($tag_path or $tag_winpath)
        and not ObfuscationBase64
        and not ObfuscationZlib
}

rule ObfuscationHighEntropyConfirmed {
    meta:
        qualification = "standalone"
        category    = "Obfuscation"
        subcategory = "Code Obfuscation (high confidence)"
        priority    = 3
        evidence    = "high entropy + exec/eval/decode callable — strong obfuscation signal"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $ent_text  = /entropy>=[0-9]+\.[0-9]/
        $exec_kw   = /\b(exec|eval|compile|__import__)\b/  nocase
        $decode_kw = /\b(decode|decompress|b64decode)\b/   nocase

        $tag_path    = "has_path"
        $tag_winpath = "has_windows_path"

    condition:
        math.entropy(0, filesize) > 5.0
        and $ent_text
        and (any of ($exec_kw, $decode_kw))
        and not ($tag_path or $tag_winpath)
        and not ObfuscationBase64
        and not ObfuscationZlib
}


// ════════════════════════════════════════════════════════════════════
// Priority 4 — Suspicious LoC
// ════════════════════════════════════════════════════════════════════






// ══════════════════════════════════════════════════════════════════════════════
//       https://bandit.readthedocs.io/en/latest/blacklists/
// ══════════════════════════════════════════════════════════════════════════════


rule ObfuscationCharEncoding {
    meta:
        qualification = "labeling"
        category    = "Obfuscation"
        subcategory = "Character Encoding Obfuscation"
        priority    = 3
        evidence    = "hex/octal char encoding or chr() join — GuardDog obfuscation.yml pattern"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $hex_seq    = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/
        $chr_join   = /['"]{1}\.join\s*\(\s*chr\s*\(/
        $chr_concat = /chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(/
        $getattr_b  = /getattr\s*\(\s*__builtins__/

    condition:
        any of them
}


rule ObfuscationAPIIndirection {
    meta:
        qualification = "labeling"
        category    = "Obfuscation"
        subcategory = "API Indirection Obfuscation"
        priority    = 3
        evidence    = "__dict__/__getattribute__/getattr indirection — GuardDog api-obfuscation.yml pattern"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $dict_acc   = /__dict__\s*\[/
        $getattrib  = /__getattribute__\s*\(/
        $dunder_imp = /__import__\s*\(\s*["'][^"']{1,32}["']\s*\)/

    condition:
        any of them
}



rule ExfiltrateSensitiveData {
    meta:
        qualification = "standalone"
        category    = "Network Connection"
        subcategory = "Sensitive Data Exfiltration"
        priority    = 1
        evidence    = "env/credential read + network send — GuardDog exfiltrate-sensitive-data.yml pattern"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $env_read   = "os.environ"
        $getenv     = /os\.getenv\s*\(/
        $aws_cred   = ".aws/credentials"
        $ssh_key    = /\.ssh[\/\\](id_rsa|authorized_keys)/

        $req_post   = /requests\.(post|put|patch)\s*\(/    nocase
        $urllib_op  = /urllib\.request\.urlopen\s*\(/
        $sock_send  = /\.(sendall|sendto)\s*\(/

    condition:
        any of ($env_read, $getenv, $aws_cred, $ssh_key) and
        any of ($req_post, $urllib_op, $sock_send)
}


rule DownloadAndExecute {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Remote Download and Execute"
        priority    = 1
        evidence    = "remote download + chmod executable — GuardDog download-executable.yml pattern"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $urlretr    = /urllib\.request\.urlretrieve\s*\(/
        $req_get    = /requests\.get\s*\(/
        $urlopen    = /urlopen\s*\(/

        $chmod_x    = /os\.chmod\s*\(.{1,60}0o?[67][57][57]/

        $exec_sub   = /subprocess\.(run|Popen|call)\s*\(/
        $exec_os    = /os\.(system|execv)\s*\(/

    condition:
        any of ($urlretr, $req_get, $urlopen) and
        ($chmod_x or any of ($exec_sub, $exec_os))
}


rule SilentProcessExecution {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Silent Process Execution"
        priority    = 1
        evidence    = "subprocess with stdio redirected to DEVNULL — GuardDog silent-process-execution.yml pattern"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $sub_func   = /subprocess\.(run|Popen|call|check_call|check_output)\s*\(/
        $devnull    = "DEVNULL"
        $stdout_dn  = /stdout\s*=\s*subprocess\.DEVNULL/
        $stderr_dn  = /stderr\s*=\s*subprocess\.DEVNULL/

    condition:
        $sub_func and $devnull and
        ($stdout_dn or $stderr_dn)
}


rule ShadyExternalDomain {
    meta:
        qualification = "labeling"
        category    = "Network Connection"
        subcategory = "Suspicious External Domain"
        priority    = 1
        evidence    = "known C2/exfil/webhook domain — GuardDog shady-links.yml pattern"
        benign      = 0
        malicious   = 1

    strings:
        $ngrok      = "ngrok.io"            nocase
        $webhook    = "webhook.site"        nocase
        $burp       = "burpcollaborator"    nocase
        $discord    = "discord.com/api"     nocase
        $pastebin   = "pastebin.com"        nocase
        $transfer   = "transfer.sh"         nocase
        $catbox     = "catbox.moe"          nocase
        $ipinfo     = "ipinfo.io"           nocase
        $ifconfig   = "ifconfig.me"         nocase
        $telegram   = "api.telegram.org"    nocase

    condition:
        any of them
}



rule WeakDeserializationAlternative {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "Alternative Deserialization"
        priority    = 1
        evidence    = "dill/shelve/jsonpickle/pandas.read_pickle — Bandit B301 extended"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $dill_l     = /\bdill\.loads?\b/          nocase
        $shelve_o   = /\bshelve\.open\b/           nocase
        $jpickle    = /\bjsonpickle\.decode\b/     nocase
        $pd_pickle  = /\bpandas\.read_pickle\b/    nocase
        $marshal_l  = /\bmarshal\.load\b/          nocase

    condition:
        any of them
}


rule ClipboardScreenCapture {
    meta:
        qualification = "labeling"
        category    = "Network Connection"
        subcategory = "User Surveillance"
        priority    = 1
        evidence    = "clipboard read or screen capture — GuardDog clipboard-access.yml / screenshot.yml pattern"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $pyperclip  = /pyperclip\.(paste|copy)\s*\(/    nocase
        $imgrab     = /ImageGrab\.grab\s*\(/             nocase
        $pyscrsht   = "pyscreenshot"                     nocase
        $pyautogui  = /pyautogui\.screenshot\s*\(/       nocase
        $mss_cap    = /mss\.mss\s*\(\)/                  nocase

    condition:
        any of them
}



rule GTFOBinUnixExec {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "GTFOBins Unix Proxy Execution"
        priority    = 1
        evidence    = "awk/xargs/vim/nmap/env shell escape — GTFOBins Unix execution vector"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        // awk 'BEGIN{system("/bin/sh")}'
        $awk_sys  = /\bawk\b.{0,300}BEGIN\s*\{.{0,300}system\s*\(/    nocase
        // xargs -I {} bash -c '...'
        $xargs_sh = /\bxargs\b.{0,200}-[Ii]\b.{0,200}(bash|sh)\s+-c/ nocase
        // vim -c ':!cmd' or :system(...)
        $vim_exec = /\bvi(m)?\b.{0,300}(-c\s+.{0,10}:!|:system\s*\()/ nocase
        // nmap --script-exec / --script=exec
        $nmap_scr = /\bnmap\b.{0,400}(--script-exec|--script\s*=)/    nocase
        // env bash -c '...'
        $env_sh   = /\benv\b.{0,50}(bash|sh|python|perl)\s+-[ci]/     nocase

    condition:
        any of them
}


rule LOLBASWindowsScriptHost {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Windows Script Host Execution"
        priority    = 1
        evidence    = "wscript/cscript VBS/JScript execution — LOLBAS T1216 / WSH proxy"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $wscript = /\bwscript(\.exe)?\b/                               nocase
        $cscript = /\bcscript(\.exe)?\b/                               nocase
        $vbs     = /\.(vbs|js|jse|vbe|wsf)\b/                         nocase
        $engine  = /(\/\/e:|\/\/engine:)(jscript|vbscript)/            nocase

    condition:
        ($wscript or $cscript) and ($vbs or $engine)
}


rule LOLBASMshtaExec {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "MSHTA HTA Execution"
        priority    = 1
        evidence    = "mshta.exe vbscript:/javascript: inline or remote HTA — LOLBAS T1218.005"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $mshta   = /\bmshta(\.exe)?\b/                                 nocase
        $vbs_url = "vbscript:"                                         nocase
        $js_url  = "javascript:"                                        nocase
        $hta_url = /https?:\/\/[^\s"']{4,}\.hta\b/                    nocase

    condition:
        $mshta and ($vbs_url or $js_url or $hta_url)
}


rule LOLBASNetAssemblyExec {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = ".NET Assembly Proxy Execution"
        priority    = 1
        evidence    = "InstallUtil/regasm/regsvcs /U or /codebase — LOLBAS T1218.004/T1218.009/T1218.010"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $installutil = /\bInstallUtil(\.exe)?\b/                       nocase
        $regasm      = /\bregasm(\.exe)?\b/                            nocase
        $regsvcs     = /\bregsvcs(\.exe)?\b/                           nocase
        $uninstall   = /\/(U|uninstall)\b/                             nocase
        $codebase    = /\/codebase\b/                                  nocase

    condition:
        any of ($installutil, $regasm, $regsvcs) and ($uninstall or $codebase)
}


rule LOLBASFileDownload {
    meta:
        qualification = "labeling"
        category    = "Network Connection"
        subcategory = "LOLBAS Uncommon Download"
        priority    = 1
        evidence    = "desktopimgdownldr/esentutl/ieexec/odbcconf/forfiles — uncommon LOLBAS download/exec vectors"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $deskdown   = /\bdesktopimgdownldr(\.exe)?\b.{0,200}\/lockscreenurl:/ nocase
        $esentutl   = /\besentutl(\.exe)?\b.{0,200}(\/y|\/vss)\b/    nocase
        $ieexec     = /\bieexec(\.exe)?\b.{0,200}https?:\/\//         nocase
        $odbcconf   = /\bodbcconf(\.exe)?\b.{0,300}(REGSVR|\/a\b)/   nocase
        $forfiles_c = /\bforfiles(\.exe)?\b.{0,400}\/c\b.{0,200}cmd\b/ nocase

    condition:
        any of them
}



rule ExecBase64TaintChain {
    meta:
        qualification = "standalone"
        category    = "Code Execution"
        subcategory = "Base64 Taint Chain Execution"
        priority    = 1
        evidence    = "base64/codecs/marshal+zlib decode source → exec/eval/subprocess/os sink — GuardDog exec-base64.yml"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        // base64.b64decode(...)
        $src_b64d       = /\bbase64\.b64decode\s*\(/                        nocase
        $src_str_dec    = /["']\.decode\s*\(\s*["'][^"']{1,32}["']\s*\)/    nocase
        $src_codecs     = /\bcodecs\.decode\s*\(/                            nocase
        // importlib.import_module('base64').b64decode(...)
        $src_import_b64 = /import_module\s*\(\s*['"]base64['"]\s*\)/        nocase
        $src_marshal_z  = /\bmarshal\.loads\s*\(\s*\S*zlib\.decompress/     nocase

        $sink_exec      = /\bexec\s*\(/                                      nocase
        $sink_eval      = /\beval\s*\(/                                      nocase
        $sink_sub_run   = /\bsubprocess\.(run|call|check_output|Popen)\s*\(/ nocase
        $sink_os_sys    = /\bos\.(system|popen|execl|execv|spawnl|posix_spawn)\s*\(/ nocase

    condition:
        any of ($src_*) and any of ($sink_*)
}


rule PyArmorObfuscation {
    meta:
        qualification = "labeling"
        category    = "Obfuscation"
        subcategory = "PyArmor Obfuscation"
        priority    = 3
        evidence    = "__pyarmor__ / pytransform / pyarmor_runtime / __armor_enter__ — GuardDog pyarmor.yml"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $pyarmor_call   = /\b__pyarmor__\s*\(/                       nocase
        // from pytransform import pyarmor_runtime
        $pytransform    = /\bpytransform\b/                          nocase
        $runtime_call   = /\bpyarmor_runtime\b/                      nocase
        // from pyarmor_runtime_xxxxx import __pyarmor__
        $runtime_import = /pyarmor_runtime[_\w]*\s+import\s+__pyarmor__/ nocase
        $armor_enter    = "__armor_enter__"
        $armor_exit     = "__armor_exit__"
        $pyarmor_enter  = "__pyarmor_enter__"
        $pyarmor_exit   = "__pyarmor_exit__"
        $check_armored  = /\bcheck_armored\s*\(/                     nocase
        $assert_armored = /\bassert_armored\s*\(/                    nocase

    condition:
        any of them
}


rule DLLHijackingInjection {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "DLL Hijacking / Process Injection"
        priority    = 1
        evidence    = "WriteProcessMemory/CreateRemoteThread/LoadLibraryA/CDLL/LD_PRELOAD or MITRE T1218 LOLBin — GuardDog dll-hijacking.yml"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        $write_pm   = "WriteProcessMemory"       nocase
        $create_rt  = "CreateRemoteThread"       nocase
        $load_lib   = "LoadLibraryA"             nocase
        $cdll_kw    = /\bCDLL\s*\(/              nocase
        $ctypes_kw  = /\bctypes\b/               nocase

        $ld_preload = "LD_PRELOAD"               nocase

        // ── MITRE T1218 — Signed Binary Proxy Execution LOLBin ────────
        $lolbin_rundll  = /\brundll32(\.exe)?\b/  nocase
        $lolbin_regsvr  = /\bregsvr32(\.exe)?\b/  nocase
        $lolbin_msiexec = /\bmsiexec(\.exe)?\b/   nocase
        $lolbin_mshta   = /\bmshta(\.exe)?\b/     nocase
        $lolbin_cmstp   = /\bcmstp(\.exe)?\b/     nocase
        $lolbin_mavinj  = /\bmavinject(\.exe)?\b/ nocase

        $wb_open    = /open\s*\(.{0,80}['"]wb['"]/  nocase

    condition:
        $write_pm or $create_rt or $load_lib
        or ($ctypes_kw and $cdll_kw)
        or $ld_preload
        or (2 of ($lolbin_*))
        or ($wb_open and any of ($lolbin_*))
}


rule SensitiveFileAccess {
    meta:
        qualification = "labeling"
        category    = "Network Connection"
        subcategory = "Sensitive File Access"
        priority    = 1
        evidence    = "/etc/passwd CLI read or programmatic file open — GuardDog suspicious_passwd_access_linux.yar"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        // CLI: cat/less/more/head/tail /etc/passwd
        $cli_passwd  = /(cat|less|more|head|tail)\s+.{0,100}\/etc\/passwd/ nocase
        $open_passwd = /open\s*\(\s*['"]\/etc\/passwd/                     nocase
        $read_passwd = /(readFile|readFileSync)\s*\(\s*['"]\/etc\/passwd/   nocase
        $shadow      = /\/etc\/shadow\b/                                    nocase
        $sudoers     = /\/etc\/sudoers\b/                                   nocase

    condition:
        any of them
}


//        Poisoning Stealthy Again" (Liu et al.)

rule PICKLECLOAKAceGadget {
    meta:
        qualification = "labeling"
        category    = "Code Execution"
        subcategory = "PICKLECLOAK ACE Gadget"
        priority    = 1
        evidence    = "Known PICKLECLOAK ACE gadget callable — eval/exec/subprocess wrapper bypassing scanner denylist"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        // asyncio subprocess wrapper
        $asyncio_sp = /\basyncio(\.unix_events)?\._UnixSubprocessTransport\b/ nocase
        // distutils subprocess
        $distspawn  = /\bdistutils\.spawn\.spawn\b/                            nocase
        // profiling wrappers → internally call exec/eval
        $cprofile   = /\bcProfile\.(run|runctx)\b/                             nocase
        $cprofile_p = /\bcProfile\.Profile\.(run|runctx)\b/                    nocase
        $profile_r  = /\bprofile\.(run|runctx)\b/                              nocase
        $profile_p  = /\bprofile\.Profile\.(run|runctx)\b/                     nocase
        // trace wrappers
        $trace_run  = /\btrace\.Trace\.(run|runctx)\b/                         nocase
        $trace_wrf  = /\btrace\.CoverageResults\.write_results_file\b/         nocase
        // pydoc wrappers
        $pydoc_pp   = /\bpydoc\.(pipepager|locate|safeimport|tempfilepager)\b/ nocase
        // logging config
        $logging_ih = /\blogging\.config\.(_install_handlers|_resolve)\b/      nocase
        // unittest
        $unittest_g = /\bunittest\.loader\.TestLoader\._get_module_from_name\b/ nocase
        $unittest_m = /\bunittest\.mock\._importer\b/                           nocase
        // numpy eval wrappers
        $numpy_get  = /\bnumpy\.f2py\.capi_maps\.getinit\b/                    nocase
        $numpy_eval = /\bnumpy\.f2py\.crackfortran\.(myeval|_eval_scalar)\b/   nocase
        $numpy_exec = /\bnumpy\.distutils\.(exec_command\._exec_command|cpuinfo\.getoutput|cpuinfo\.command_by_line|misc_util\.get_cmd)\b/ nocase
        // sympy eval wrappers
        $sympy_sym  = /\bsympy\.(sympify|utilities\.lambdify\.lambdify|parsing\.sympy_parser\.eval_expr)\b/ nocase
        // code/idle execution
        $code_run   = /\bcode\.InteractiveInterpreter\.runcode\b/              nocase
        $idlelib_r  = /\bidlelib\.(run\.Executive\.runcode|calltip\.get_entity|autocomplete\.AutoComplete\.get_entity)\b/ nocase
        // uuid / osx / cgitb subprocess
        $misc_ace   = /\b(uuid\._get_command_stdout|_osx_support\._read_output|cgitb\.lookup|dataclasses\._create_fn)\b/ nocase

    condition:
        any of them
}

rule PICKLECLOAKAfwGadget {
    meta:
        qualification = "labeling"
        category    = "File Operation"
        subcategory = "PICKLECLOAK Arbitrary File Write"
        priority    = 1
        evidence    = "Known PICKLECLOAK AFW gadget callable — file write wrapper bypassing scanner denylist"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        // XML write
        $xml_write  = /\bxml\.etree\.ElementTree\.(ElementTree\.write|_serialize_xml|_serialize_html)\b/ nocase
        // numpy/scipy save — public alias and internal path
        $np_savetxt = /\bnumpy\.(savetxt|save|savez|lib\.npyio\.savetxt)\b/   nocase
        // distutils write
        $dist_write = /\bdistutils\.(file_util\.(write_file|_copy_file_contents)|tests\.support\.TempdirManager\.write_file)\b/ nocase
        // test helper
        $test_make  = /\btest\.support\.script_helper\.make_script\b/         nocase
        // profiling dump
        $prof_dump  = /\b(tracemalloc\.Snapshot\.dump|profile\.Profile\.dump_stats)\b/ nocase
        // pipes / mailbox write
        $pipes_mbox = /\b(pipes\.Template\.open_w|mailbox\._create_carefully)\b/ nocase
        // http cookiejar
        $http_save  = /\bhttp\.cookiejar\.LWPCookieJar\.save\b/               nocase

    condition:
        any of them
}

rule PICKLECLOAKAfrGadget {
    meta:
        qualification = "labeling"
        category    = "File Operation"
        subcategory = "PICKLECLOAK Arbitrary File Read"
        priority    = 1
        evidence    = "Known PICKLECLOAK AFR gadget callable — file read wrapper bypassing scanner denylist"
        benign      = 0
        malicious   = 0
        observed    = "no firing on the measured corpus"

    strings:
        // urllib file/URL read
        $urllib_op  = /\burllib\.request\.(URLopener\.(open|retrieve)|FileHandler\.open_local_file)\b/ nocase
        // XML parse (file source)
        $xml_parse  = /\bxml\.(dom\.pulldom\.parse|sax\.saxutils\.prepare_input_source|etree\.ElementInclude\.default_loader)\b/ nocase
        // numpy read — public aliases and internal paths
        $np_load    = /\bnumpy\.(memmap|load|loadtxt|lib\.npyio\.loadtxt|ma\.mrecords\.openfile|distutils\.conv_template\.resolve_includes)\b/ nocase
        // pandas read — public aliases and internal paths
        $pd_read    = /\bpandas\.(read_csv|read_table|read_fwf|read_pickle|io\.(parsers\.readers\.(read_csv|read_table|read_fwf)|common\.get_handle))\b/ nocase
        // argparse file
        $argparse_f = /\bargparse\.FileType\.__call__\b/                       nocase
        // pipes/shlex/mailbox read
        $misc_read  = /\b(pipes\.Template\.open_r|shlex\.shlex\.sourcehook|mailbox\.MH\.(get_bytes|get_file)|pkgutil\.ImpLoader\.get_data)\b/ nocase
        // pydoc
        $pydoc_url  = /\bpydoc\._url_handler\b/                               nocase

    condition:
        any of them
}

// ══════════════════════════════════════════════════════════════════════════
//
//   SuspiciousLocShareware / SuspiciousLocPathTraversal /
//   SuspiciousLocExecution / SuspiciousLocLoadFile
//
// ══════════════════════════════════════════════════════════════════════════

