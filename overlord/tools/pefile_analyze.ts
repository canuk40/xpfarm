import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"
import path from "path"
import fs from "fs"
import { instrumentedCall } from "./lib/tool_instrument"

export default tool({
  description: "Analyze Windows PE (Portable Executable) files — inspect headers, sections, imports, exports, resources, and detect packers",
  args: {
    binary: tool.schema.string().describe("Path to the PE file (.exe, .dll, .sys)"),
    analysis: tool.schema.enum(["overview", "imports", "exports", "sections", "resources", "strings", "full"]).default("overview").describe("Type of analysis to perform"),
    timeout: tool.schema.number().default(60).describe("Timeout in seconds"),
  },
  async execute(args, context) {
    const binaryPath = args.binary.startsWith("/") ? args.binary : path.join(context.directory, args.binary)
    return instrumentedCall({ toolName: "pefile_analyze", binary: binaryPath, args }, async () => {
      const startTime = Date.now()
      try {
        const scriptMap: Record<string, string> = {
          overview: `
import pefile, json, sys
pe = pefile.PE('${binaryPath}')
info = pe.dump_info()
print(json.dumps({
  'machine': hex(pe.FILE_HEADER.Machine),
  'timestamp': pe.FILE_HEADER.TimeDateStamp,
  'subsystem': pe.OPTIONAL_HEADER.Subsystem,
  'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
  'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
  'num_sections': pe.FILE_HEADER.NumberOfSections,
  'is_dll': pe.is_dll(),
  'is_exe': pe.is_exe(),
  'warnings': pe.get_warnings(),
}))`,
          imports: `
import pefile, json
pe = pefile.PE('${binaryPath}')
imports = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode('utf-8', errors='replace')
    imports[dll] = [imp.name.decode('utf-8', errors='replace') if imp.name else f'ordinal_{imp.ordinal}' for imp in entry.imports]
print(json.dumps(imports))`,
          exports: `
import pefile, json
pe = pefile.PE('${binaryPath}')
exports = []
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
  for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    exports.append({'name': exp.name.decode('utf-8', errors='replace') if exp.name else None, 'ordinal': exp.ordinal, 'address': hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)})
print(json.dumps(exports))`,
          sections: `
import pefile, json
pe = pefile.PE('${binaryPath}')
sections = [{'name': s.Name.decode('utf-8', errors='replace').strip(), 'vaddr': hex(s.VirtualAddress), 'vsize': s.Misc_VirtualSize, 'raw_size': s.SizeOfRawData, 'entropy': round(s.get_entropy(), 2), 'characteristics': hex(s.Characteristics)} for s in pe.sections]
print(json.dumps(sections))`,
          resources: `
import pefile, json
pe = pefile.PE('${binaryPath}')
resources = []
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
  def walk(entry, depth=0):
    if hasattr(entry, 'directory'):
      for e in entry.directory.entries:
        walk(e, depth+1)
    elif hasattr(entry, 'data'):
      r = entry.data.struct
      resources.append({'type': str(entry.id), 'rva': hex(r.OffsetToData), 'size': r.Size})
  for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    walk(entry)
print(json.dumps(resources))`,
          strings: `
import pefile, json, re
pe = pefile.PE('${binaryPath}')
data = pe.__data__
strings = list(set(re.findall(b'[\\x20-\\x7e]{4,}', data)))
strings = [s.decode('ascii', errors='replace') for s in strings[:500]]
print(json.dumps(strings))`,
          full: `
import pefile, json
pe = pefile.PE('${binaryPath}')
imports = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode('utf-8', errors='replace')
    imports[dll] = [imp.name.decode('utf-8', errors='replace') if imp.name else f'ordinal_{imp.ordinal}' for imp in entry.imports]
sections = [{'name': s.Name.decode('utf-8', errors='replace').strip(), 'vaddr': hex(s.VirtualAddress), 'entropy': round(s.get_entropy(), 2)} for s in pe.sections]
print(json.dumps({'machine': hex(pe.FILE_HEADER.Machine), 'is_dll': pe.is_dll(), 'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), 'sections': sections, 'imports': imports, 'warnings': pe.get_warnings()}))`,
        }

        const scriptPath = "/tmp/pefile_analyze.py"
        fs.writeFileSync(scriptPath, scriptMap[args.analysis])

        const result = await $`python3 ${scriptPath}`.nothrow().timeout(args.timeout * 1000 + 5000)
        const stdout = result.stdout?.toString() || ""
        const stderr = result.stderr?.toString() || ""

        let data: any
        try { data = JSON.parse(stdout) } catch { data = { raw: stdout } }

        return JSON.stringify({
          success: result.exitCode === 0,
          binary: binaryPath,
          analysis: args.analysis,
          data,
          duration: Date.now() - startTime,
          stderr: stderr.slice(0, 500) || undefined,
        }, null, 2)
      } catch (error: any) {
        return JSON.stringify({ success: false, error: error.message || String(error), duration: Date.now() - startTime }, null, 2)
      }
    })
  }
})
