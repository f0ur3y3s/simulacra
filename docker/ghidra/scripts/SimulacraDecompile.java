// Decompile functions of the current program and write them as one JSON document.
//
// Arguments: <output json> <file with one function name per line; empty = all functions>
//
// Output: {"program", "format", "compiler_spec", "image_base", "functions": [
//   {"name", "entry" (offset from image base), "signature", "calling_convention",
//    "c" (decompiled text), "callees", "error"} ...]}
//
// @category simulacra
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class SimulacraDecompile extends GhidraScript {

    private static final int TIMEOUT_SECONDS = 60;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("usage: SimulacraDecompile <out.json> <names.txt>");
        }
        Set<String> wanted = new HashSet<>();
        for (String line : Files.readAllLines(Path.of(args[1]), StandardCharsets.UTF_8)) {
            if (!line.isBlank()) {
                wanted.add(line.strip());
            }
        }

        DecompInterface ifc = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(false);
        if (!ifc.openProgram(currentProgram)) {
            throw new IllegalStateException("decompiler failed to open program: "
                    + ifc.getLastMessage());
        }

        long base = currentProgram.getImageBase().getOffset();
        List<String> items = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) {
                continue;
            }
            if (!wanted.isEmpty() && !wanted.contains(f.getName())) {
                continue;
            }
            items.add(describe(ifc, f, base));
        }
        ifc.dispose();

        StringBuilder out = new StringBuilder();
        out.append("{\"program\":").append(q(currentProgram.getName()))
           .append(",\"format\":").append(q(currentProgram.getExecutableFormat()))
           .append(",\"compiler_spec\":")
           .append(q(currentProgram.getCompilerSpec().getCompilerSpecID().toString()))
           .append(",\"image_base\":").append(base)
           .append(",\"functions\":[").append(String.join(",", items)).append("]}\n");
        Files.writeString(Path.of(args[0]), out.toString(), StandardCharsets.UTF_8);
    }

    private String describe(DecompInterface ifc, Function f, long base) {
        String c = "";
        String error = "";
        // The database prototype is often still `undefined f(void)`; the decompiler's recovered
        // one is what the pseudo-C actually uses.
        String signature = f.getSignature().getPrototypeString();
        try {
            DecompileResults res = ifc.decompileFunction(f, TIMEOUT_SECONDS, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                c = res.getDecompiledFunction().getC();
                String recovered = res.getDecompiledFunction().getSignature();
                if (recovered != null && !recovered.isBlank()) {
                    signature = recovered.strip().replaceAll(";$", "");
                }
            } else {
                error = res == null ? "no result" : res.getErrorMessage();
            }
        } catch (Exception e) {
            error = e.toString();
        }
        Set<String> callees = new TreeSet<>();
        for (Function callee : f.getCalledFunctions(monitor)) {
            callees.add(callee.getName());
        }
        List<String> calleeJson = new ArrayList<>();
        for (String name : callees) {
            calleeJson.add(q(name));
        }
        return "{\"name\":" + q(f.getName())
                + ",\"entry\":" + (f.getEntryPoint().getOffset() - base)
                + ",\"signature\":" + q(signature)
                + ",\"calling_convention\":" + q(f.getCallingConventionName())
                + ",\"c\":" + q(c)
                + ",\"callees\":[" + String.join(",", calleeJson) + "]"
                + ",\"error\":" + q(error == null ? "" : error) + "}";
    }

    private static String q(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        b.append(String.format("\\u%04x", (int) ch));
                    } else {
                        b.append(ch);
                    }
                }
            }
        }
        return b.append('"').toString();
    }
}
