/* workflow.sc
 * 
 * Helper functions for working with CPG
 */


import java.nio.charset.StandardCharsets._
import java.nio.file.{Files, Paths}
import io.shiftleft.passes.{CpgPass, DiffGraph}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Method


def creatingCpg(payload: String, payloadType : String) : Boolean = {
    println("[+] Check if CPG exists")
    //check if CPG exists
    if(workspace.cpgExists(payload)) {
        printf("[+] Load pre-existing CPG for %s\n", payload)
        open(payload.split("/").reverse.head)

        if(workspace.projectExists(payload)) {
            printf("[+] CPG successfully loaded for %s\n", payload)
            return true 
        } else {
            printf("[+] Failed to load CPG for %s. Deleting and moving on...\n", payload)
            delete(payload.split("/").reverse.head)
        }
    } else {
        printf("[+] No pre-existing CPGs found. Moving on...\n")
    }

    // Seems we didn't have existing CPG. Lets move on...
    payloadType match {

        case "JAR" | "WAR" | "EAR" | "JS" =>

            printf("[+] Importing Code and creating CPG for %s\n", payload) 
            importCode(payload)
            run.securityprofile
            save

            println("[+] Verify if CPG was created successfully") 
            if(!workspace.cpgExists(payload)) {
                printf("[+] Failed to create CPG for %s\n", payload)
                return false
            }
        case "CPG" => 

            println("[+] Creating CPG for " + payload)
            importCpg(payload)
            run.securityprofile
            save

            println("[+] Verify if CPG was created successfully") 
            if(!workspace.cpgExists(payload)) {
                printf("[+] Failed to create CPG for %s\n", payload)
                return false
            }

        case _ => 
            println("[+] Unrecognized payload type specified")
            return false
    }
    // we must have loaded the CPG by now or bailed out
    return true
}
