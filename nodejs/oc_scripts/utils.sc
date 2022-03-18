/* utils.sc
 * 
 * Util functions for propagating taints and common patterns
 */

import scala.annotation.tailrec
import scala.collection.mutable.ListBuffer

// pattern to detect propogation of taint via `req` variable source
val requestPattern =
  "req\\.(originalUrl|path|protocol|route|secure|signedCookies|stale|subdomains|xhr|app|pipe|file|files|baseUrl|fresh|hostname|ip|url|ips|method|body|param|params|query|cookies)"
val taintSourcePattern = "(?s)(?i).*" + requestPattern + ".*"

// pattern to detect propogation of taint via `res` variable sink
val responsePattern =
  "res\\.(append|attachment|cookie|clearCookie|download|end|format|get|json|jsonp|links|location|redirect|render|send|sendFile|sendStatus|set|status|type|vary)"
val taintSinkPattern = "(?s)(?i).*" + responsePattern + ".*"

//remove _tmp anonymous variables
val tmpRegex_1 = "\\_tmp\\_\\d+\\.".r
val tmpRegex_2 = "\\tmp\\d+\\.".r
// remove subscrips with hash based references
val subscRegex = "\\[.*\\]".r
//remove hashesets in call_expr
val kvPairs = "\\{.*\\}".r
//remove regex special characteristics
val regexChars = "[+^:,]"

//matching whole expression
val match_whole_expr = "(?s)"

case class TaintSpec(fileName: String, taintReferences: List[String])

// utilities to remove `_tmp_*, array_deref patterns form a list
def cleanTaintRef(taintRef: List[String]): List[String] = {
  taintRef
    .map(tmpRegex_1.replaceAllIn(_, ""))
    .map(tmpRegex_2.replaceAllIn(_, ""))
    .map(subscRegex.replaceAllIn(_, ""))
    .filterNot(_.contains("_tmp_"))
    .filterNot(kvPairs.matches(_))
    .map(_.replaceAll(regexChars, ""))
    .distinct
}

//get all module based sinks used in application
def getSinkByFunction(cpg: io.shiftleft.codepropertygraph.Cpg) = {
  cpg.method.name.l
    .filter(_.startsWith("^"))
    .map(_.split("\\."))
    .groupBy(i => i(0))
    .map {
      case (k, v) =>
        k -> v.flatten
          .map(i => i.replaceAll("\\(\\)", ""))
          .distinct
          .filterNot(i => i.equals(k) || i.equals("\\(\\)") || i.equals("--"))
    }
}

def transform(pattern: List[String]): String =
  pattern.map(_.replaceAll("\\*", "")).mkString("(?s)(?i).*(", "|", ").*")

def cleanAndTransform(taintRef: List[String]): String =
  transform(cleanTaintRef(taintRef))

// Function that helps construct a List of import references indexed by file
def getIdentifierRefs(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    pattern: String
): List[String] = {
  cpg.call
    .name(Operators.assignment)
    .code(pattern)
    .map(_.location.filename)
    .l
    .distinct
}

// fetch identifiers/refs and file associated with an import (keyed by file)
def identifiersInFile(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    fileName: String
): List[String] = {
  cpg.call
    .name(Operators.assignment)
    .argument
    .order(1)
    .collect {
      case arg if arg.location.filename == fileName && arg.isIdentifier =>
        arg.code.replaceAll("\\*", "")
    }
    .dedup
    .l
}

def getFileNameWithImports(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    parameter: String
): List[String] = {
  val importPattern = s""".*require\\((\\'|\\")?$parameter(\\'|\\")?\\).*"""
  getIdentifierRefs(cpg, importPattern)
}

def getImports(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    patterns: List[String]
): Map[String, List[String]] = {
  val modules = patterns.mkString("(", "|", ")")
  val importModules = patterns.map(p => s"""require\\(\"$p\"\\)""")
  val result = getFileNameWithImports(cpg, modules) map { fileName =>
    (fileName, cleanTaintRef(identifiersInFile(cpg, fileName)) ++ importModules)
  }
  result.toMap
}

// Recursive function to getch propogation of taint via derefereenced identifiers
def getRecursiveRef(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    pattern: String,
    inFile: String,
    matchPattern: String
): List[String] = {

  var accumulator = ListBuffer.empty[String]
  @tailrec def accumulateTaintFor(pattern: String): ListBuffer[String] = {
    val taintList = cpg.call
      .name(Operators.assignment)
      .where(_.argument.order(2).code(pattern))
      .argument
      .order(1)
      .where(_.file.nameExact(inFile))
      .code
      .l
      .distinct
      .sorted
    if (taintList.isEmpty) {
      accumulator
    } else {
      accumulator ++= taintList.to(ListBuffer)
      accumulateTaintFor(taintList.head)
    }
  }
  accumulateTaintFor(pattern).toList :+ matchPattern
}

def getTaintVectorsFor(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    pattern: String,
    inFile: String
): List[String] = {
  getRecursiveRef(cpg, pattern, inFile, requestPattern)
}

def getPatternVectorsFor(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    pattern: String,
    inFile: String
): List[String] = {
  getRecursiveRef(cpg, pattern, inFile, pattern)
}

def getTaintReferencesByFile(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    taintSourcePattern: String,
    fileInProject: List[String]
) = {

  fileInProject.map { file =>
    val taintList = getTaintVectorsFor(cpg, taintSourcePattern, file)
    val transformedTaintList = cleanTaintRef(taintList) :+ requestPattern
    TaintSpec(file, transformedTaintList)
  }
}

case class APIPatterns(domain : String, platform : String, keyType : String, expr : String)

//  Value based comparison of common tokens embedded in code  
val sensitiveTokenPatterns = List(  
    APIPatterns("IaaS","Amazon","S3 Object Bucket" , "s3.amazonaws.com"),
    APIPatterns("IaaS","Amazon","Access ID" , "(AKIA[0-9A-Z]{16})"),
    APIPatterns("IaaS","Amazon","MWS Auth Token" , "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    APIPatterns("Social Media","Facebook", "Access Token" , "EAACEdEose0cBA[0-9A-Za-z]+"),
    APIPatterns("Social Media","Facebook", "OAuth" , "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]"),
    APIPatterns("IaaS", "GitHub" , "Access Token", "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]"),
    APIPatterns("IaaS", "Generic" ,"API Key" , "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]"),
    APIPatterns("IaaS", "Generic" ,"Secret" , "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]"),
    APIPatterns("IaaS","Google", "API Key" , "AIza[0-9A-Za-z\\-_]{35}"),
    APIPatterns("IaaS","Google", "Cloud Platform API Key" , "AIza[0-9A-Za-z\\-_]{35}"),
    APIPatterns("IaaS","Google", "Cloud Platform OAuth" , "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"),
    APIPatterns("IaaS","Google","Drive API Key" , "AIza[0-9A-Za-z\\-_]{35}"),
    APIPatterns("IaaS","Google" ,"Drive OAuth" , "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"),
    APIPatterns("IaaS","Google", "(GCP) Service-account" , "\"type\": \"service_account\""),
    APIPatterns("IaaS","Google", "Gmail API Key" , "AIza[0-9A-Za-z\\-_]{35}"),
    APIPatterns("IaaS","Google" ,"Gmail OAuth" , "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"),
    APIPatterns("IaaS","Google" ,"OAuth Access Token" , "ya29\\.[0-9A-Za-z\\-_]+"),
    APIPatterns("Social Media","Google", "YouTube API Key" , "AIza[0-9A-Za-z\\-_]{35}"),
    APIPatterns("Social Media","Google", "YouTube OAuth" , "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"),
    APIPatterns("IaaS","Heroku", "API Key" , "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
    APIPatterns("IaaS","MailChimp", "API Key" , "[0-9a-f]{32}-us[0-9]{1,2}"),
    APIPatterns("IaaS","Mailgun" ,"API Key" , "key-[0-9a-zA-Z]{32}"),
    APIPatterns("IaaS","Generic","Password in URL" , "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"),
    APIPatterns("Finance","PayPal Braintree", "Access Token" , "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"),
    APIPatterns("ECommerce","Picatic", "API Key" , "sk_live_[0-9a-z]{32}"),
    APIPatterns("IaaS","Slack","Token" , "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"),
    APIPatterns("IaaS","Slack", "Webhook" , "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"),
    APIPatterns("IaaS","Slack","API Key" , "sk_live_[0-9a-zA-Z]{24}"),
    APIPatterns("Finance","Stripe", "Restricted API Key" , "rk_live_[0-9a-zA-Z]{24}"),
    APIPatterns("Finance", "Square", "Access Token" , "sq0atp-[0-9A-Za-z\\-_]{22}"),
    APIPatterns("Finance","Square", "OAuth Secret" , "sq0csp-[0-9A-Za-z\\-_]{43}"),
    APIPatterns("Communications", "Twilio" , "API Key" , "SK[0-9a-fA-F]{32}"),
    APIPatterns("Social Media","Twitter" ,"Access Token" , "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}"),
    APIPatterns("Social Media","Twitter", "OAuth" , "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"),
    APIPatterns("Salted Base64", "Salted Base64", "Salted Secrets", "^(U2FsdGVkX1).*")                                    // In MCSAPI via CryptoJS (for OpenSSL)
)

// Save AST graphs in SG format. Make sure Graphviz is installed!!
def saveAstGraphs(methods: List[Method], baseDir: String) = {
    os.remove.all(os.Path(baseDir))
    os.makeDir.all(os.Path(baseDir))
    methods.map { m =>
        val dotPath = os.Path(baseDir) / (m.name + m.id + ".AST.dot")
        val svgPath = os.Path(baseDir) / (m.name + m.id + ".svg")
        val dot = m.dotAst.l.head
        
        // patch the :=> and anonymous functions
        val pat = """(:=>[0-9]*|:anonymous[0-9]*)""".r
        val newDot = pat.replaceFirstIn(dot, "\"$1\"" ) // replaces first line
        os.write(dotPath, newDot)

        try {
          os.proc("dot", "-Tsvg", dotPath, "-o", svgPath).call()
        } catch {
          case e: os.SubprocessException => // silently ignore for now
        } finally {
          os.remove(dotPath)
        }
    }
}
