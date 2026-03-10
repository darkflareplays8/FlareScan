const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

// ── PE CONSTANTS ──────────────────────────────────────────────────────────────
const MZ_MAGIC = 0x5A4D
const PE_MAGIC = 0x00004550

const MACHINE_TYPES = {
  0x014c: 'x86 (i386)',
  0x8664: 'x64 (AMD64)',
  0x01c0: 'ARM',
  0xaa64: 'ARM64',
}

const SUBSYSTEMS = {
  1: 'Native',
  2: 'Windows GUI',
  3: 'Windows CUI (Console)',
  7: 'POSIX CUI',
  9: 'Windows CE GUI',
  10: 'EFI Application',
  14: 'Xbox',
}

const SECTION_FLAGS = {
  0x00000020: 'CODE',
  0x00000040: 'INITIALIZED_DATA',
  0x00000080: 'UNINITIALIZED_DATA',
  0x20000000: 'EXECUTE',
  0x40000000: 'READ',
  0x80000000: 'WRITE',
}

// Suspicious imports by DLL
const SUSPICIOUS_IMPORTS = {
  'kernel32.dll': [
    { fn: 'VirtualAlloc',          sev: 'high',   tag: 'Memory Allocation',        note: 'Allocates executable memory — common in shellcode/injectors' },
    { fn: 'VirtualAllocEx',        sev: 'high',   tag: 'Remote Memory Allocation', note: 'Allocates memory in another process — process injection' },
    { fn: 'WriteProcessMemory',    sev: 'high',   tag: 'Process Injection',        note: 'Writes to another process memory space' },
    { fn: 'CreateRemoteThread',    sev: 'critical', tag: 'Remote Thread',          note: 'Creates thread in another process — classic DLL injection' },
    { fn: 'LoadLibraryA',          sev: 'medium', tag: 'Dynamic Loading',          note: 'Loads DLL at runtime — may load malicious payload' },
    { fn: 'LoadLibraryW',          sev: 'medium', tag: 'Dynamic Loading',          note: 'Loads DLL at runtime — may load malicious payload' },
    { fn: 'GetProcAddress',        sev: 'medium', tag: 'API Resolution',           note: 'Resolves API addresses dynamically — common obfuscation technique' },
    { fn: 'CreateProcessA',        sev: 'medium', tag: 'Process Creation',         note: 'Creates new process' },
    { fn: 'CreateProcessW',        sev: 'medium', tag: 'Process Creation',         note: 'Creates new process' },
    { fn: 'IsDebuggerPresent',     sev: 'high',   tag: 'Anti-Debug',              note: 'Checks if debugger is attached — sandbox evasion' },
    { fn: 'CheckRemoteDebuggerPresent', sev: 'high', tag: 'Anti-Debug',           note: 'Checks for remote debugger — sandbox evasion' },
    { fn: 'OutputDebugStringA',    sev: 'low',    tag: 'Anti-Debug',              note: 'Debugger detection via timing' },
    { fn: 'SetUnhandledExceptionFilter', sev: 'medium', tag: 'Anti-Debug',        note: 'Overrides exception handler — used to detect debuggers' },
    { fn: 'TerminateProcess',      sev: 'medium', tag: 'Process Termination',     note: 'Force-terminates processes' },
    { fn: 'OpenProcess',           sev: 'medium', tag: 'Process Access',          note: 'Opens handle to another process' },
    { fn: 'ReadProcessMemory',     sev: 'high',   tag: 'Memory Scraping',         note: 'Reads memory from another process' },
  ],
  'advapi32.dll': [
    { fn: 'RegSetValueExA',        sev: 'high',   tag: 'Registry Write',          note: 'Writes to registry — possible persistence mechanism' },
    { fn: 'RegSetValueExW',        sev: 'high',   tag: 'Registry Write',          note: 'Writes to registry — possible persistence mechanism' },
    { fn: 'RegCreateKeyExA',       sev: 'high',   tag: 'Registry Persistence',    note: 'Creates registry key — often used for startup persistence' },
    { fn: 'RegCreateKeyExW',       sev: 'high',   tag: 'Registry Persistence',    note: 'Creates registry key — often used for startup persistence' },
    { fn: 'CryptEncrypt',          sev: 'high',   tag: 'Encryption',              note: 'Encrypts data — may be used for ransomware or C2 comms' },
    { fn: 'CryptDecrypt',          sev: 'medium', tag: 'Decryption',              note: 'Decrypts data — may unpack embedded payload' },
    { fn: 'OpenSCManagerA',        sev: 'high',   tag: 'Service Manager',         note: 'Opens service control manager — service-based persistence' },
    { fn: 'CreateServiceA',        sev: 'critical', tag: 'Service Install',       note: 'Installs a Windows service — persistent execution' },
    { fn: 'AdjustTokenPrivileges', sev: 'high',   tag: 'Privilege Escalation',    note: 'Modifies process privileges' },
  ],
  'wininet.dll': [
    { fn: 'InternetOpenA',         sev: 'medium', tag: 'Network Access',          note: 'Initializes WinINet — network communication' },
    { fn: 'InternetConnectA',      sev: 'medium', tag: 'Network Connect',         note: 'Opens internet connection' },
    { fn: 'HttpSendRequestA',      sev: 'high',   tag: 'HTTP Request',            note: 'Sends HTTP request — potential C2 communication' },
    { fn: 'InternetReadFile',      sev: 'medium', tag: 'Data Download',           note: 'Downloads data from internet' },
    { fn: 'InternetWriteFile',     sev: 'high',   tag: 'Data Upload',             note: 'Uploads data — potential exfiltration' },
  ],
  'ws2_32.dll': [
    { fn: 'connect',               sev: 'medium', tag: 'Socket Connect',          note: 'Opens TCP/IP connection' },
    { fn: 'send',                  sev: 'medium', tag: 'Socket Send',             note: 'Sends data over socket' },
    { fn: 'recv',                  sev: 'medium', tag: 'Socket Receive',          note: 'Receives data over socket' },
    { fn: 'WSAStartup',            sev: 'low',    tag: 'Winsock Init',            note: 'Initializes Windows Sockets' },
    { fn: 'gethostbyname',         sev: 'medium', tag: 'DNS Lookup',              note: 'Resolves hostname — C2 domain lookup' },
  ],
  'ntdll.dll': [
    { fn: 'NtWriteVirtualMemory',  sev: 'critical', tag: 'Process Injection',    note: 'Low-level memory write to another process' },
    { fn: 'NtCreateThreadEx',      sev: 'critical', tag: 'Stealth Thread',        note: 'Creates thread bypassing security hooks' },
    { fn: 'NtUnmapViewOfSection',  sev: 'high',   tag: 'Process Hollowing',       note: 'Unmaps process memory — process hollowing technique' },
    { fn: 'NtAllocateVirtualMemory', sev: 'high', tag: 'Memory Allocation',       note: 'Low-level memory allocation — shellcode staging' },
    { fn: 'RtlDecompressBuffer',   sev: 'medium', tag: 'Decompression',           note: 'Decompresses data — may unpack embedded payload' },
  ],
  'shell32.dll': [
    { fn: 'ShellExecuteA',         sev: 'medium', tag: 'Shell Execution',         note: 'Executes file/URL via shell — may launch malicious payload' },
    { fn: 'ShellExecuteW',         sev: 'medium', tag: 'Shell Execution',         note: 'Executes file/URL via shell — may launch malicious payload' },
  ],
  'psapi.dll': [
    { fn: 'EnumProcesses',         sev: 'medium', tag: 'Process Enumeration',     note: 'Lists all running processes — reconnaissance' },
    { fn: 'GetModuleFileNameExA',  sev: 'low',    tag: 'Process Enumeration',     note: 'Gets module path for process' },
  ],
  'crypt32.dll': [
    { fn: 'CryptStringToBinaryA',  sev: 'medium', tag: 'Data Decode',             note: 'Decodes Base64/hex strings — payload decoding' },
    { fn: 'CertOpenSystemStoreA',  sev: 'high',   tag: 'Certificate Store',       note: 'Opens certificate store — credential theft possible' },
  ],
  'dpapi.dll': [
    { fn: 'CryptUnprotectData',    sev: 'critical', tag: 'DPAPI Decrypt',         note: 'Decrypts DPAPI-protected data — browser passwords, tokens' },
    { fn: 'CryptProtectData',      sev: 'medium', tag: 'DPAPI Encrypt',           note: 'Encrypts data with DPAPI' },
  ],
}

// Suspicious string patterns
const STRING_PATTERNS = [
  { re: /powershell/i,                       sev: 'high',   tag: 'PowerShell',         note: 'References PowerShell — may execute PS commands' },
  { re: /-[Ee]nc(odedcommand)?/i,            sev: 'critical', tag: 'Encoded PS',       note: 'Encoded PowerShell command — obfuscated execution' },
  { re: /-[Ww]indow[Ss]tyle\s+[Hh]idden/i,  sev: 'high',   tag: 'Hidden Window',      note: 'Hides PowerShell window — stealth execution' },
  { re: /cmd\.exe/i,                         sev: 'medium', tag: 'CMD Execution',      note: 'References cmd.exe' },
  { re: /[Cc]ookies/,                        sev: 'high',   tag: 'Cookie Access',      note: 'References browser cookie storage' },
  { re: /[Ll]ogins\.json/,                   sev: 'high',   tag: 'Firefox Creds',      note: 'References Firefox login database' },
  { re: /[Kk]ey4\.db/,                       sev: 'high',   tag: 'Firefox Key DB',     note: 'References Firefox encryption key database' },
  { re: /[Ww]allet/,                         sev: 'high',   tag: 'Crypto Wallet',      note: 'References cryptocurrency wallet' },
  { re: /\bseed phrase\b/i,                  sev: 'critical', tag: 'Seed Phrase',      note: 'References wallet seed phrase — crypto theft' },
  { re: /HKCU\\.*\\Run/i,                    sev: 'high',   tag: 'Run Key',            note: 'Hardcoded Run registry key — persistence' },
  { re: /HKLM\\.*\\Run/i,                    sev: 'high',   tag: 'Run Key (System)',   note: 'System-level Run key — elevated persistence' },
  { re: /[Ss]chtasks/,                       sev: 'high',   tag: 'Scheduled Task',     note: 'Creates scheduled task — persistence' },
  { re: /[Nn]et(cat|\.exe)?\s+-e/i,          sev: 'critical', tag: 'Reverse Shell',    note: 'Netcat reverse shell pattern' },
  { re: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/, sev: 'medium', tag: 'Hardcoded IP', note: 'Hardcoded IP address — possible C2' },
  { re: /http:\/\/(?!www\.(microsoft|windows|google)\.)[\w\-.]+\.\w{2,}/i, sev: 'medium', tag: 'HTTP URL', note: 'Hardcoded HTTP URL — possible C2 or download' },
  { re: /https?:\/\/.*\.(ru|cn|tk|top|xyz|club|pw|cc)\b/i, sev: 'high', tag: 'Suspicious TLD', note: 'URL with high-risk TLD' },
  { re: /[Ss]tart-[Pp]rocess/,              sev: 'medium', tag: 'PS Start-Process',   note: 'PowerShell process spawning' },
  { re: /[Ii]nvoke-[Ee]xpression|iex\b/,   sev: 'critical', tag: 'IEX Execution',    note: 'Invoke-Expression — arbitrary PS code execution' },
  { re: /[Ii]nvoke-[Ww]ebRequest|wget|curl/i, sev: 'medium', tag: 'Web Download',    note: 'Downloads files from web' },
  { re: /[Uu]ser[Dd]ata\\[Gg]oogle/,        sev: 'critical', tag: 'Chrome Data',      note: 'References Chrome user data — credential theft' },
  { re: /[Mm]ozilla\\[Ff]irefox/,           sev: 'high',   tag: 'Firefox Data',       note: 'References Firefox profile — credential theft' },
  { re: /[Bb]itcoin|[Ee]thereum|[Mm]onero/i, sev: 'high',  tag: 'Crypto Reference',  note: 'References cryptocurrency' },
  { re: /[Rr]untime\.exec|[Pp]rocess\.start/i, sev: 'medium', tag: 'Runtime Exec',   note: 'Runtime process execution' },
  { re: /\\[Tt]emp\\/,                       sev: 'low',    tag: 'Temp Directory',    note: 'References Windows Temp folder — staging' },
  { re: /[Dd]isable[Aa]nti[Ss]py|[Dd]isable[Dd]efender/i, sev: 'critical', tag: 'Disable AV', note: 'Attempts to disable Windows Defender/AV' },
  { re: /[Vv]irt[Uu]al[Bb]ox|[Vv][Mm][Ww]are|[Ss]andbox/i, sev: 'high',  tag: 'VM Detection', note: 'Checks for VM/sandbox environment — evasion' },
  { re: /[Ss][Ee][Tt]-[Mm][Pp][Pp]reference/i, sev: 'critical', tag: 'Disable Defender', note: 'Disables Windows Defender via PowerShell' },
  { re: /[Nn][Ee][Tt]\s+user.*\/add/i,       sev: 'critical', tag: 'User Creation',   note: 'Creates new system user — backdoor' },
  { re: /[Nn][Ee][Tt]\s+localgroup\s+[Aa]dministrators/i, sev: 'critical', tag: 'Admin Escalation', note: 'Adds user to Administrators group' },
  { re: /[Bb]ase64/i,                        sev: 'medium', tag: 'Base64',            note: 'Base64 encoding/decoding — payload obfuscation' },
  { re: /[Uu][Nn][Hh][Oo][Ll][Yy]/i,        sev: 'high',   tag: 'Unholy Pattern',    note: 'Known malware string' },
]

// ── ENTROPY ───────────────────────────────────────────────────────────────────
function calcEntropy(buf) {
  if (!buf.length) return 0
  const freq = new Array(256).fill(0)
  for (const b of buf) freq[b]++
  let entropy = 0
  for (const f of freq) {
    if (f === 0) continue
    const p = f / buf.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

// ── STRING EXTRACTOR ──────────────────────────────────────────────────────────
function extractStrings(buf, minLen = 5) {
  const strings = []
  let current = ''
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]
    if (b >= 0x20 && b <= 0x7e) {
      current += String.fromCharCode(b)
    } else {
      if (current.length >= minLen) strings.push(current)
      current = ''
    }
  }
  if (current.length >= minLen) strings.push(current)
  return strings
}

// ── PE PARSER ─────────────────────────────────────────────────────────────────
function parsePE(buf) {
  const result = {
    valid: false,
    arch: 'Unknown',
    subsystem: 'Unknown',
    isDLL: false,
    compiledAt: null,
    sections: [],
    imports: {},
    exports: [],
    entryPoint: 0,
    imageBase: 0,
    characteristics: [],
  }

  if (buf.length < 64) return result

  // MZ header
  const mzMagic = buf.readUInt16LE(0)
  if (mzMagic !== MZ_MAGIC) return result

  const peOffset = buf.readUInt32LE(0x3c)
  if (peOffset + 24 > buf.length) return result

  const peMagic = buf.readUInt32LE(peOffset)
  if (peMagic !== PE_MAGIC) return result

  result.valid = true

  // COFF header (after PE signature)
  const coffOffset = peOffset + 4
  const machine = buf.readUInt16LE(coffOffset)
  const numSections = buf.readUInt16LE(coffOffset + 2)
  const timestamp = buf.readUInt32LE(coffOffset + 4)
  const sizeOfOptHeader = buf.readUInt16LE(coffOffset + 16)
  const characteristics = buf.readUInt16LE(coffOffset + 18)

  result.arch = MACHINE_TYPES[machine] || `Unknown (0x${machine.toString(16)})`
  result.compiledAt = new Date(timestamp * 1000).toISOString()
  result.isDLL = (characteristics & 0x2000) !== 0

  if (characteristics & 0x0002) result.characteristics.push('EXECUTABLE')
  if (characteristics & 0x2000) result.characteristics.push('DLL')
  if (characteristics & 0x0100) result.characteristics.push('32BIT_MACHINE')
  if (characteristics & 0x0020) result.characteristics.push('LARGE_ADDRESS_AWARE')

  // Optional header
  const optOffset = coffOffset + 20
  if (sizeOfOptHeader > 0 && optOffset + 4 <= buf.length) {
    const magic = buf.readUInt16LE(optOffset)
    const is64 = magic === 0x020b
    result.entryPoint = buf.readUInt32LE(optOffset + 16)

    if (is64 && optOffset + 24 + 8 <= buf.length) {
      result.imageBase = Number(buf.readBigUInt64LE(optOffset + 24))
    } else if (!is64 && optOffset + 28 <= buf.length) {
      result.imageBase = buf.readUInt32LE(optOffset + 28)
    }

    const subsystemOffset = is64 ? optOffset + 68 : optOffset + 68
    if (subsystemOffset + 2 <= buf.length) {
      const sub = buf.readUInt16LE(subsystemOffset)
      result.subsystem = SUBSYSTEMS[sub] || `Unknown (${sub})`
    }

    // Data directories — get import table RVA
    const dataDirOffset = is64 ? optOffset + 112 : optOffset + 96
    let importRVA = 0
    let exportRVA = 0
    if (dataDirOffset + 8 <= buf.length) {
      exportRVA = buf.readUInt32LE(dataDirOffset)
      importRVA = buf.readUInt32LE(dataDirOffset + 8)
    }

    // Parse sections
    const sectionTableOffset = optOffset + sizeOfOptHeader
    for (let i = 0; i < numSections && i < 32; i++) {
      const secOff = sectionTableOffset + i * 40
      if (secOff + 40 > buf.length) break

      const nameBytes = buf.slice(secOff, secOff + 8)
      const name = nameBytes.toString('utf8').replace(/\0/g, '')
      const virtualSize = buf.readUInt32LE(secOff + 8)
      const virtualAddress = buf.readUInt32LE(secOff + 12)
      const rawSize = buf.readUInt32LE(secOff + 16)
      const rawOffset = buf.readUInt32LE(secOff + 20)
      const sectionFlags = buf.readUInt32LE(secOff + 36)

      const sectionData = rawSize > 0 && rawOffset + rawSize <= buf.length
        ? buf.slice(rawOffset, rawOffset + Math.min(rawSize, 65536))
        : Buffer.alloc(0)

      const entropy = calcEntropy(sectionData)

      const flagList = []
      for (const [flag, label] of Object.entries(SECTION_FLAGS)) {
        if (sectionFlags & parseInt(flag)) flagList.push(label)
      }

      result.sections.push({
        name,
        virtualAddress: '0x' + virtualAddress.toString(16).padStart(8, '0'),
        rawSize,
        entropy: entropy.toFixed(2),
        flags: flagList,
        suspicious: entropy > 7.0,
      })
    }

    // Parse imports (RVA → file offset)
    if (importRVA && result.sections.length) {
      const importData = parseImports(buf, importRVA, result.sections)
      result.imports = importData
    }

    // Parse exports
    if (exportRVA && result.sections.length) {
      result.exports = parseExports(buf, exportRVA, result.sections)
    }
  }

  return result
}

function rvaToOffset(rva, sections) {
  for (const sec of sections) {
    const va = parseInt(sec.virtualAddress, 16)
    const rawSize = sec.rawSize
    if (rva >= va && rva < va + rawSize) {
      return rva - va + /* rawOffset */ 0 // we'll compute inline
    }
  }
  return -1
}

function parseImports(buf, importRVA, sections) {
  const imports = {}

  // Find section containing the import RVA
  for (const sec of sections) {
    const va = parseInt(sec.virtualAddress, 16)
    const rawOff = findSectionRawOffset(buf, sec.name)
    if (rawOff < 0) continue

    if (importRVA < va || importRVA >= va + sec.rawSize) continue

    let offset = rawOff + (importRVA - va)

    // Walk import descriptor table
    while (offset + 20 <= buf.length) {
      const iltRVA     = buf.readUInt32LE(offset)
      const nameRVA    = buf.readUInt32LE(offset + 12)
      const iatRVA     = buf.readUInt32LE(offset + 16)

      if (!iltRVA && !nameRVA && !iatRVA) break // null terminator

      // Resolve DLL name
      const nameOff = resolveRVA(buf, nameRVA, sections)
      if (nameOff < 0 || nameOff >= buf.length) { offset += 20; continue }

      let dllName = ''
      for (let i = nameOff; i < buf.length && buf[i]; i++) dllName += String.fromCharCode(buf[i])
      dllName = dllName.toLowerCase()

      imports[dllName] = imports[dllName] || []

      // Walk ILT/IAT
      const thunkRVA = iltRVA || iatRVA
      if (thunkRVA) {
        const thunkOff = resolveRVA(buf, thunkRVA, sections)
        if (thunkOff >= 0) {
          let ti = thunkOff
          while (ti + 4 <= buf.length) {
            const thunk = buf.readUInt32LE(ti)
            if (!thunk) break
            if (thunk & 0x80000000) {
              // Ordinal import
              imports[dllName].push(`#${thunk & 0xffff}`)
            } else {
              const hintOff = resolveRVA(buf, thunk, sections)
              if (hintOff >= 0 && hintOff + 2 < buf.length) {
                let fn = ''
                for (let i = hintOff + 2; i < buf.length && buf[i]; i++) fn += String.fromCharCode(buf[i])
                if (fn) imports[dllName].push(fn)
              }
            }
            ti += 4
          }
        }
      }

      offset += 20
    }
    break
  }

  return imports
}

function parseExports(buf, exportRVA, sections) {
  const exports = []
  const off = resolveRVA(buf, exportRVA, sections)
  if (off < 0 || off + 40 > buf.length) return exports

  const numFunctions = buf.readUInt32LE(off + 20)
  const numNames = buf.readUInt32LE(off + 24)
  const namePointerRVA = buf.readUInt32LE(off + 32)

  const nameTableOff = resolveRVA(buf, namePointerRVA, sections)
  if (nameTableOff < 0) return exports

  for (let i = 0; i < Math.min(numNames, 200); i++) {
    const nameRVA = buf.readUInt32LE(nameTableOff + i * 4)
    const nameOff = resolveRVA(buf, nameRVA, sections)
    if (nameOff < 0) continue
    let name = ''
    for (let j = nameOff; j < buf.length && buf[j]; j++) name += String.fromCharCode(buf[j])
    if (name) exports.push(name)
  }

  return exports
}

function resolveRVA(buf, rva, sections) {
  for (const sec of sections) {
    const va = parseInt(sec.virtualAddress, 16)
    const rawOff = findSectionRawOffset(buf, sec.name)
    if (rawOff < 0) continue
    if (rva >= va && rva < va + sec.rawSize) {
      return rawOff + (rva - va)
    }
  }
  return -1
}

// Re-parse the section table to get raw offsets (sections obj doesn't store it)
const _rawOffsetCache = new WeakMap()
function findSectionRawOffset(buf, sectionName) {
  if (buf.length < 64) return -1
  const peOffset = buf.readUInt32LE(0x3c)
  const coffOffset = peOffset + 4
  const numSections = buf.readUInt16LE(coffOffset + 2)
  const sizeOfOptHeader = buf.readUInt16LE(coffOffset + 16)
  const sectionTableOffset = coffOffset + 20 + sizeOfOptHeader

  for (let i = 0; i < numSections && i < 32; i++) {
    const secOff = sectionTableOffset + i * 40
    if (secOff + 40 > buf.length) break
    const name = buf.slice(secOff, secOff + 8).toString('utf8').replace(/\0/g, '')
    if (name === sectionName) {
      return buf.readUInt32LE(secOff + 20)
    }
  }
  return -1
}

// ── MAIN ANALYZER ─────────────────────────────────────────────────────────────
function analyze(filePath) {
  const buf = fs.readFileSync(filePath)
  const stat = fs.statSync(filePath)

  const sha256 = crypto.createHash('sha256').update(buf).digest('hex')
  const md5    = crypto.createHash('md5').update(buf).digest('hex')

  const overallEntropy = calcEntropy(buf)
  const strings = extractStrings(buf)
  const pe = parsePE(buf)

  // ── Check suspicious imports ──
  const importFindings = []
  for (const [dll, fns] of Object.entries(pe.imports)) {
    const knownDll = SUSPICIOUS_IMPORTS[dll]
    if (!knownDll) continue
    for (const fn of fns) {
      const match = knownDll.find(k => k.fn === fn)
      if (match) {
        importFindings.push({ dll, fn, ...match })
      }
    }
  }

  // ── Check suspicious strings ──
  const stringFindings = []
  const seenTags = new Set()
  for (const str of strings) {
    for (const pattern of STRING_PATTERNS) {
      if (pattern.re.test(str)) {
        if (!seenTags.has(pattern.tag)) {
          stringFindings.push({ string: str.slice(0, 120), ...pattern })
          seenTags.add(pattern.tag)
        }
        break
      }
    }
  }

  // ── Check sections ──
  const sectionFindings = []
  for (const sec of pe.sections) {
    if (sec.suspicious) {
      sectionFindings.push({
        sev: 'high',
        tag: 'High Entropy Section',
        note: `Section "${sec.name}" has entropy ${sec.entropy}/8.0 — possible packed/encrypted payload`,
        section: sec.name,
        entropy: sec.entropy,
      })
    }
    // Executable + writable (shellcode staging)
    if (sec.flags.includes('EXECUTE') && sec.flags.includes('WRITE')) {
      sectionFindings.push({
        sev: 'high',
        tag: 'RWX Section',
        note: `Section "${sec.name}" is both WRITE and EXECUTE — classic shellcode/injection staging`,
        section: sec.name,
      })
    }
  }

  // ── Suspicious timestamp ──
  const miscFindings = []
  if (pe.valid && pe.compiledAt) {
    const compiled = new Date(pe.compiledAt)
    const now = new Date()
    const age = (now - compiled) / (1000 * 60 * 60 * 24)
    if (age < 7) {
      miscFindings.push({
        sev: 'medium',
        tag: 'Very Recent Compile',
        note: `Binary compiled ${Math.round(age)} day(s) ago — freshly built executables are higher risk`,
      })
    }
    if (compiled.getFullYear() < 2000 || compiled.getFullYear() > 2030) {
      miscFindings.push({
        sev: 'medium',
        tag: 'Invalid Compile Timestamp',
        note: `Compile timestamp (${pe.compiledAt}) is implausible — often set to zero or epoch to hinder analysis`,
      })
    }
  }

  // No imports at all (packed)
  if (pe.valid && Object.keys(pe.imports).length === 0) {
    miscFindings.push({
      sev: 'high',
      tag: 'No Visible Imports',
      note: 'No import table found — binary is likely packed or obfuscated; resolves APIs at runtime',
    })
  }

  if (overallEntropy > 7.2) {
    miscFindings.push({
      sev: 'high',
      tag: 'High File Entropy',
      note: `Overall file entropy is ${overallEntropy.toFixed(2)}/8.0 — likely packed, encrypted, or compressed`,
    })
  }

  // ── Score calculation ──
  const allFindings = [
    ...importFindings.map(f => ({ ...f, source: 'import' })),
    ...stringFindings.map(f => ({ ...f, source: 'string' })),
    ...sectionFindings.map(f => ({ ...f, source: 'section' })),
    ...miscFindings.map(f => ({ ...f, source: 'misc' })),
  ]

  const SEV_WEIGHTS = { critical: 20, high: 10, medium: 5, low: 2 }
  let rawScore = 0
  for (const f of allFindings) rawScore += SEV_WEIGHTS[f.sev] || 0
  const score = Math.min(100, rawScore)

  let verdict = 'clean'
  if (score >= 60) verdict = 'malicious'
  else if (score >= 25) verdict = 'suspicious'

  // ── Category breakdown ──
  const categories = {}
  for (const f of allFindings) {
    const cat = categorizeFinding(f.tag)
    categories[cat] = (categories[cat] || 0) + 1
  }

  return {
    file: {
      name: path.basename(filePath),
      size: stat.size,
      sha256,
      md5,
      analyzedAt: new Date().toISOString(),
    },
    pe: {
      valid: pe.valid,
      arch: pe.arch,
      subsystem: pe.subsystem,
      isDLL: pe.isDLL,
      compiledAt: pe.compiledAt,
      sections: pe.sections,
      importedDLLs: Object.keys(pe.imports),
      exportCount: pe.exports.length,
      characteristics: pe.characteristics,
    },
    analysis: {
      score,
      verdict,
      entropy: parseFloat(overallEntropy.toFixed(2)),
      stringCount: strings.length,
      findings: allFindings,
      categories,
    },
    strings: strings.filter(s => s.length > 8).slice(0, 500),
  }
}

function categorizeFinding(tag) {
  const map = {
    'Anti-Debug': 'Evasion',
    'VM Detection': 'Evasion',
    'Sleep Obfuscation': 'Evasion',
    'High Entropy Section': 'Evasion',
    'High File Entropy': 'Evasion',
    'No Visible Imports': 'Evasion',
    'Invalid Compile Timestamp': 'Evasion',
    'RWX Section': 'Evasion',
    'Encoded PS': 'Evasion',
    'Base64': 'Evasion',
    'Process Injection': 'Injection',
    'Remote Thread': 'Injection',
    'Remote Memory Allocation': 'Injection',
    'Process Hollowing': 'Injection',
    'Stealth Thread': 'Injection',
    'DLL Inject': 'Injection',
    'Registry Write': 'Persistence',
    'Registry Persistence': 'Persistence',
    'Run Key': 'Persistence',
    'Run Key (System)': 'Persistence',
    'Scheduled Task': 'Persistence',
    'Service Install': 'Persistence',
    'Cookie Access': 'Credential Access',
    'Firefox Creds': 'Credential Access',
    'Firefox Key DB': 'Credential Access',
    'Firefox Data': 'Credential Access',
    'Chrome Data': 'Credential Access',
    'DPAPI Decrypt': 'Credential Access',
    'Certificate Store': 'Credential Access',
    'Crypto Wallet': 'Credential Access',
    'Seed Phrase': 'Credential Access',
    'Network Access': 'Network/C2',
    'Network Connect': 'Network/C2',
    'HTTP Request': 'Network/C2',
    'Data Upload': 'Network/C2',
    'Data Download': 'Network/C2',
    'Socket Connect': 'Network/C2',
    'Socket Send': 'Network/C2',
    'DNS Lookup': 'Network/C2',
    'Hardcoded IP': 'Network/C2',
    'HTTP URL': 'Network/C2',
    'Suspicious TLD': 'Network/C2',
    'Reverse Shell': 'Network/C2',
    'Privilege Escalation': 'Privilege Escalation',
    'Disable AV': 'Defense Evasion',
    'Disable Defender': 'Defense Evasion',
    'User Creation': 'Persistence',
    'Admin Escalation': 'Privilege Escalation',
    'Process Enumeration': 'Discovery',
    'Very Recent Compile': 'Misc',
  }
  return map[tag] || 'Misc'
}

module.exports = { analyze }
