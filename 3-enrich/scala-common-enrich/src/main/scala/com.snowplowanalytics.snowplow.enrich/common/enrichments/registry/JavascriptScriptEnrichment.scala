/*
 * Copyright (c) 2012-2014 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.snowplowanalytics
package snowplow
package enrich
package common
package enrichments
package registry

// Scripting
import javax.script.{
  ScriptEngineManager,
  ScriptException,
  Bindings,
  Compilable,
  CompiledScript
}

// Maven Artifact
import org.apache.maven.artifact.versioning.DefaultArtifactVersion

// Jackson
import org.codehaus.jackson.JsonParseException

// Scala
import scala.util.control.NonFatal

// Scalaz
import scalaz._
import Scalaz._

// json4s
import org.json4s._
import org.json4s.jackson.JsonMethods

// Iglu
import iglu.client.{
  SchemaCriterion,
  SchemaKey
}
import iglu.client.validation.ProcessingMessageMethods._

// This project
import outputs.EnrichedEvent
import utils.{
  ScalazJson4sUtils,
  ConversionUtils,
  JsonUtils => JU
}

/**
* Companion object. Lets us create a JavascriptScriptEnrichment
* from a JValue.
*/
// TODO: split most of this into a JavaScriptEnrichment object
// used by both the Config option and the case class.
object JavascriptScriptEnrichmentConfig extends ParseableEnrichment {

  val supportedSchema = SchemaCriterion("com.snowplowanalytics.snowplow", "javascript_script_config", "jsonschema", 1, 0)

  object Variables {
    private val prefix = "$snowplow31337" // To avoid collisions
    val In  = s"${prefix}In"
    val Out = s"${prefix}Out"
  }

  object Engines {
    private val factory = new ScriptEngineManager
    val Raw = factory.getEngineByName("JavaScript")
    val Compiling = Raw.asInstanceOf[Compilable]
  }

  /**
   * Creates a JavascriptScriptEnrichment instance from a JValue.
   *
   * @param config The JavaScript script enrichment JSON
   * @param schemaKey The SchemaKey provided for the enrichment
   *        Must be a supported SchemaKey for this enrichment
   * @return a configured JavascriptScriptEnrichment instance
   */
  def parse(config: JValue, schemaKey: SchemaKey): ValidatedNelMessage[JavascriptScriptEnrichment] = {
    isParseable(config, schemaKey).flatMap( conf => {
      (for {
        encoded  <- ScalazJson4sUtils.extract[String](config, "parameters", "script")
        raw      <- ConversionUtils.decodeBase64Url("script", encoded).toProcessingMessage // TODO: shouldn't be URL-safe
        compiled <- compile(raw)
        enrich    = JavascriptScriptEnrichment(compiled)
      } yield enrich).toValidationNel
    })
  }

  /**
   * Appends an invocation to the script and
   * then attempts to compile it.
   */
  def compile(script: String): ValidatedMessage[CompiledScript] = {

    // Script mustn't be null
    if (Option(script).isEmpty) {
      return "JavaScript script for evaluation is null".fail.toProcessingMessage
    }

    val invoke =
      s"""|// User-supplied script
          |${script}
          |
          |// Immediately invoke using reserved args
          |${Variables.Out} = process(${Variables.In});
          |
          |// Don't return anything
          |null;
          |""".stripMargin

    try {
      Engines.Compiling.compile(invoke).success
    } catch {
      case se: ScriptException => s"Error compiling JavaScript script: [${se}]".fail.toProcessingMessage
    }
  }

}

/**
 * Config for an JavaScript script enrichment
 *
 * @param script The compiled script ready for
 */
case class JavascriptScriptEnrichment(
  script: CompiledScript
  ) extends Enrichment {

  val version = new DefaultArtifactVersion("0.1.0")

  implicit val formats = DefaultFormats

  import JavascriptScriptEnrichmentConfig._

  /**
   * Run the process function against the
   * supplied EnrichedEvent.
   *
   * @param event The enriched event to
   *        pass into our process function
   * @return a Validation boxing either a
   *         JSON array of contexts on Success,
   *         or an error String on Failure
   */
  def process(event: EnrichedEvent): Validation[String, List[JObject]] = {

    val bindings = Engines.Raw.createBindings
    bindings.put(Variables.In, event)

    // Fail fast
    try {
      val retVal = script.eval(bindings)
      if (Option(retVal).isDefined) {
        return s"Evaluated JavaScript script should not return a value; returned: [${retVal}]".fail
      }
    } catch {
      case NonFatal(nf) =>
        return s"Evaluating JavaScript script threw an exception: [${nf}]".fail
    }
    if (!bindings.containsKey(Variables.Out)) {
      return s"Evaluated JavaScript script is missing out-variable ${Variables.Out}; should never happen".fail
    }

    Option(bindings.get(Variables.Out)) match {
      case None => Nil.success
      case Some(obj) => {
        try {
          Extraction.decompose(obj) match {
            case JArray(elements) => elements match {
              case l: List[JObject] => l.success // TODO: implement this correctly (because type erasure)
              case _ => s"JavaScript script's return Array must contain objects; got [${obj}]".fail
            }
            case _ => s"JavaScript script must return an Array; got [${obj}]".fail
          }
        } catch {
          case NonFatal(nf) =>
            s"Could not convert object returned from JavaScript script to JValue AST: [${nf}]".fail
        }
      }
    }
  }

}
