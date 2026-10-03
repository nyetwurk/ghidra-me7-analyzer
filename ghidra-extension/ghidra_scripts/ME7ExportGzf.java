// Export the saved current program as <dir>/<name>.gzf (script argument: dir).
// @category ME7
import java.io.File;

import ghidra.app.script.GhidraScript;

public class ME7ExportGzf extends GhidraScript {
    @Override
    public void run() throws Exception {
        File out = new File(getScriptArgs()[0], currentProgram.getName() + ".gzf");
        out.delete();
        currentProgram.getDomainFile().packFile(out, monitor);
        if (!out.isFile()) {
            throw new Exception("export failed: " + out);
        }
        println("exported " + out);
    }
}
