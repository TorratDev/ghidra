// Dump the open program to JSON plus a binary sidecar (memory block bytes), read-only.
//
// Usage: analyzeHeadless <projdir> <project> -process <program> -readOnly -noanalysis \
//          -scriptPath scripts/export -postScript ExportProject.java <outdir>
// Writes <outdir>/export.json and <outdir>/export.bin (default outdir: the current directory).
// Compiled by Ghidra against its own jars; written for Ghidra 11.4.3.
// @category Export

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

public class ExportProject extends GhidraScript {
	private static final int CHUNK = 1 << 20;

	private PrintWriter out;
	private final Map<String, DataType> types = new TreeMap<>(); // keyed by path name, so output is sorted
	private final Set<String> visited = new HashSet<>();

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File dir = new File(args.length > 0 ? args[0] : ".");
		dir.mkdirs();
		File binFile = new File(dir, "export.bin");
		File jsonFile = new File(dir, "export.json");

		List<MemoryBlock> blocks = new ArrayList<>(Arrays.asList(currentProgram.getMemory().getBlocks()));
		blocks.sort(Comparator.comparing(MemoryBlock::getStart)); // javadoc gives no order
		Map<MemoryBlock, long[]> placed = new HashMap<>(); // block -> {file offset, length}
		String sidecarSha = writeSidecar(binFile, blocks, placed);

		try (PrintWriter w = new PrintWriter(new BufferedWriter(
			new OutputStreamWriter(new FileOutputStream(jsonFile), StandardCharsets.UTF_8), 1 << 16))) {
			out = w;
			out.print("{\n");
			writeProgram(binFile, sidecarSha);
			out.print(",\n\"memory_blocks\": ");
			writeBlocks(blocks, placed);
			out.print(",\n\"symbols\": ");
			writeSymbols();
			out.print(",\n\"functions\": ");
			writeFunctions();
			out.print(",\n\"data_types\": ");
			writeTypes();
			out.print("\n}\n");
		}
		println("export: wrote " + jsonFile + " and " + binFile);
	}

	// Initialized blocks only, in address order, in chunks.
	private String writeSidecar(File f, List<MemoryBlock> blocks, Map<MemoryBlock, long[]> placed)
			throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		long pos = 0;
		byte[] buf = new byte[CHUNK];
		try (OutputStream os = new BufferedOutputStream(new FileOutputStream(f))) {
			for (MemoryBlock b : blocks) {
				if (!b.isInitialized()) {
					continue;
				}
				long size = b.getSize();
				for (long done = 0; done < size; ) {
					monitor.checkCancelled();
					int n = (int) Math.min(CHUNK, size - done);
					int got = b.getBytes(b.getStart().add(done), buf, 0, n);
					if (got != n) {
						throw new IOException("short read in block " + b.getName() + " at +" + done);
					}
					os.write(buf, 0, n);
					md.update(buf, 0, n);
					done += n;
				}
				placed.put(b, new long[] { pos, size });
				pos += size;
			}
		}
		return hex(md.digest());
	}

	private void writeProgram(File bin, String sha) {
		out.print("\"project\": " + q(state.getProject() == null ? null : state.getProject().getName()));
		out.print(",\n\"program\": " + q(currentProgram.getName()));
		out.print(",\n\"ghidra_version\": " + q(Application.getApplicationVersion()));
		out.print(",\n\"language\": " + q(currentProgram.getLanguageID().getIdAsString()));
		out.print(",\n\"compiler_spec\": " + q(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()));
		out.print(",\n\"image_base\": " + q(currentProgram.getImageBase().toString(true)));
		out.print(",\n\"executable_md5\": " + q(currentProgram.getExecutableMD5()));
		out.print(",\n\"function_count\": " + currentProgram.getFunctionManager().getFunctionCount());
		out.print(",\n\"sidecar\": {\"file\": " + q(bin.getName()) + ", \"sha256\": " + q(sha) + "}");
	}

	private void writeBlocks(List<MemoryBlock> blocks, Map<MemoryBlock, long[]> placed) {
		out.print("[");
		String sep = "\n";
		for (MemoryBlock b : blocks) {
			out.print(sep);
			sep = ",\n";
			out.print("{\"name\": " + q(b.getName()) + ", \"start\": " + q(b.getStart().toString(true)) +
				", \"size\": " + b.getSize() +
				", \"read\": " + b.isRead() + ", \"write\": " + b.isWrite() + ", \"execute\": " + b.isExecute() +
				", \"type\": " + q(b.getType().toString()) +
				", \"initialized\": " + b.isInitialized() + ", \"volatile\": " + b.isVolatile() +
				", \"overlay\": " + b.isOverlay());
			long[] p = placed.get(b);
			out.print(p == null ? ", \"sidecar_offset\": null, \"sidecar_length\": null"
				: ", \"sidecar_offset\": " + p[0] + ", \"sidecar_length\": " + p[1]);
			out.print("}");
		}
		out.print("\n]");
	}

	private void writeSymbols() throws Exception {
		List<Symbol> syms = new ArrayList<>();
		SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s == null) { // next() returns null at the end
				break;
			}
			syms.add(s);
		}
		syms.sort(Comparator.<Symbol, Integer>comparing(s -> s.getAddress() == Address.NO_ADDRESS ? 0 : 1)
			.thenComparing((Symbol s) -> s.getAddress())
			.thenComparing((Symbol s) -> s.getName())
			.thenComparingInt(s -> s.getSymbolType().getID())
			.thenComparing((Symbol s) -> String.join("::", s.getPath())));
		out.print("[");
		String sep = "\n";
		for (Symbol s : syms) {
			monitor.checkCancelled();
			out.print(sep);
			sep = ",\n";
			out.print("{\"name\": " + q(s.getName()) + ", \"address\": " + addr(s.getAddress()) +
				", \"type_id\": " + s.getSymbolType().getID() + ", \"type\": " + q(s.getSymbolType().toString()) +
				", \"namespace\": " + nsPath(s.getParentNamespace()) +
				", \"source\": " + q(s.getSource().toString()) + ", \"primary\": " + s.isPrimary() + "}");
		}
		out.print("\n]");
	}

	private void writeFunctions() throws Exception {
		out.print("[");
		String sep = "\n";
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true); // ascending address
		while (it.hasNext()) {
			monitor.checkCancelled();
			Function f = it.next();
			out.print(sep);
			sep = ",\n";
			out.print("{\"entry\": " + addr(f.getEntryPoint()) + ", \"name\": " + q(f.getName()) +
				", \"namespace\": " + nsPath(f.getParentNamespace()) +
				", \"calling_convention\": " + q(f.getCallingConventionName()) +
				", \"thunk\": " + f.isThunk() + ", \"varargs\": " + f.hasVarArgs() +
				", \"no_return\": " + f.hasNoReturn() + ", \"custom_storage\": " + f.hasCustomVariableStorage() +
				", \"body\": [");
			String rs = "";
			for (AddressRange r : f.getBody().getAddressRanges()) {
				out.print(rs + "{\"start\": " + addr(r.getMinAddress()) + ", \"end\": " + addr(r.getMaxAddress()) + "}");
				rs = ", ";
			}
			out.print("], \"prototype\": " + q(f.getPrototypeString(true, true)) +
				", \"return_type\": " + typeRef(f.getReturnType()) + ", \"return_storage\": " + q(f.getReturn().getVariableStorage().toString()) +
				", \"parameters\": [");
			rs = "";
			for (Parameter p : f.getParameters()) {
				out.print(rs + "{\"ordinal\": " + p.getOrdinal() + ", \"name\": " + q(p.getName()) +
					", \"data_type\": " + typeRef(p.getDataType()) + ", \"storage\": " + q(p.getVariableStorage().toString()) + "}");
				rs = ", ";
			}
			out.print("]}");
		}
		out.print("\n]");
	}

	// A reference is the data type's path name; the definition goes into the data_types table.
	private String typeRef(DataType dt) {
		collect(dt);
		return q(dt.getPathName());
	}

	private void collect(DataType dt) {
		if (dt == null || !visited.add(dt.getPathName())) {
			return;
		}
		types.put(dt.getPathName(), dt);
		if (dt instanceof TypeDef) {
			collect(((TypeDef) dt).getBaseDataType());
		}
		else if (dt instanceof Pointer) {
			collect(((Pointer) dt).getDataType());
		}
		else if (dt instanceof Array) {
			collect(((Array) dt).getDataType());
		}
		else if (dt instanceof Composite) {
			for (DataTypeComponent c : ((Composite) dt).getDefinedComponents()) {
				collect(c.getDataType());
			}
		}
		else if (dt instanceof FunctionDefinition) {
			FunctionDefinition fd = (FunctionDefinition) dt;
			collect(fd.getReturnType());
			for (ParameterDefinition p : fd.getArguments()) {
				collect(p.getDataType());
			}
		}
	}

	private void writeTypes() {
		out.print("[");
		String sep = "\n";
		for (DataType dt : types.values()) {
			out.print(sep);
			sep = ",\n";
			// No universal ID: Ghidra generates a new one per session for types it creates on the fly
			// (e.g. "undefined"), which would make two exports differ.
			out.print("{\"name\": " + q(dt.getName()) + ", \"path_name\": " + q(dt.getPathName()) +
				", \"category_path\": " + q(dt.getCategoryPath().getPath()) + ", \"length\": " + dt.getLength() +
				", \"alignment\": " + dt.getAlignment() + ", \"description\": " + q(dt.getDescription()) +
				", \"kind\": " + q(kind(dt)));
			if (dt instanceof TypeDef) {
				out.print(", \"base\": " + q(((TypeDef) dt).getBaseDataType().getPathName()));
			}
			else if (dt instanceof Pointer) {
				DataType t = ((Pointer) dt).getDataType();
				out.print(", \"base\": " + (t == null ? "null" : q(t.getPathName())));
			}
			else if (dt instanceof Array) {
				Array a = (Array) dt;
				out.print(", \"base\": " + q(a.getDataType().getPathName()) + ", \"elements\": " + a.getNumElements() +
					", \"element_length\": " + a.getElementLength());
			}
			else if (dt instanceof Composite) {
				out.print(", \"components\": [");
				String cs = "";
				for (DataTypeComponent c : ((Composite) dt).getDefinedComponents()) {
					out.print(cs + "{\"ordinal\": " + c.getOrdinal() + ", \"offset\": " + c.getOffset() +
						", \"name\": " + q(c.getFieldName()) + ", \"data_type\": " + q(c.getDataType().getPathName()) +
						", \"length\": " + c.getLength() + "}");
					cs = ", ";
				}
				out.print("]");
			}
			else if (dt instanceof FunctionDefinition) {
				FunctionDefinition fd = (FunctionDefinition) dt;
				out.print(", \"return_type\": " + q(fd.getReturnType().getPathName()) + ", \"parameters\": [");
				String ps = "";
				for (ParameterDefinition p : fd.getArguments()) {
					out.print(ps + "{\"ordinal\": " + p.getOrdinal() + ", \"name\": " + q(p.getName()) +
						", \"data_type\": " + q(p.getDataType().getPathName()) + "}");
					ps = ", ";
				}
				out.print("]");
			}
			out.print("}");
		}
		out.print("\n]");
	}

	private static String kind(DataType dt) {
		for (Class<?> c : new Class<?>[] { TypeDef.class, Pointer.class, Array.class, Structure.class, Union.class,
			FunctionDefinition.class, ghidra.program.model.data.Enum.class }) {
			if (c.isInstance(dt)) {
				return c.getSimpleName();
			}
		}
		return "Other";
	}

	private static String addr(Address a) {
		return a == null || a == Address.NO_ADDRESS ? "null" : q(a.toString(true));
	}

	// Namespace path from the outermost namespace down; the global namespace is the empty list.
	private static String nsPath(Namespace ns) {
		Deque<String> names = new ArrayDeque<>();
		for (; ns != null && !ns.isGlobal(); ns = ns.getParentNamespace()) {
			names.addFirst(ns.getName());
		}
		StringBuilder sb = new StringBuilder("[");
		for (String n : names) {
			sb.append(sb.length() > 1 ? ", " : "").append(q(n));
		}
		return sb.append("]").toString();
	}

	private static String q(String s) {
		if (s == null) {
			return "null";
		}
		StringBuilder sb = new StringBuilder("\"");
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"': sb.append("\\\""); break;
				case '\\': sb.append("\\\\"); break;
				case '\n': sb.append("\\n"); break;
				case '\r': sb.append("\\r"); break;
				case '\t': sb.append("\\t"); break;
				default:
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
			}
		}
		return sb.append('"').toString();
	}

	private static String hex(byte[] b) {
		StringBuilder sb = new StringBuilder();
		for (byte x : b) {
			sb.append(String.format("%02x", x));
		}
		return sb.toString();
	}
}
