import $file.workflow
import $file.utils

import java.nio.file.Paths

def executeSP(cpg: Cpg, resultFile: String) = {
    cpg.runScript(Paths.get(".", "oc_scripts").toAbsolutePath + "/jsrules.sc")
	cpg.finding.p |> resultFile
	cpg.finding.toJsonPretty |> resultFile.replace(".md", ".json")
}

@main def execute(payload: String, payloadType: String, resultFile: String) : Boolean = {
    if(workflow.creatingCpg(payload,payloadType)) {
    	executeSP(cpg, resultFile)
    	printf("[✔] Saved results to %s\n", resultFile)
	}
	return true
}
