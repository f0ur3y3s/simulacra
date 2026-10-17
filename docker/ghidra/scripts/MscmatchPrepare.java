// Pre-analysis options for mscmatch.
//
// Decompiler Parameter ID is off by default. It decompiles every function during analysis
// and commits recovered parameters and calling conventions, so a caller that passes an
// argument straight through to a callee defined in the same binary still shows it.
//
// @category mscmatch
import ghidra.app.script.GhidraScript;

public class MscmatchPrepare extends GhidraScript {
    @Override
    protected void run() throws Exception {
        setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true");
    }
}
