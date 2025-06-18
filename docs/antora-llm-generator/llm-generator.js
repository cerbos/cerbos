"use strict";

const { NodeHtmlMarkdown } = require("node-html-markdown");

const nhm = new NodeHtmlMarkdown();

/**
 * An Antora extension that generates a single text file containing all the
 * content of the site, suitable for consumption by an LLM.
 */
module.exports.register = function (context) {
  const logger = context.getLogger("llm-generator");

  context.on("navigationBuilt", ({ contentCatalog, siteCatalog }) => {
    console.log("LLM Generator: Assembling content for LLM text files.");

    let indexContent = "# Cerbos\n\n##Docs";
    let fullContent = "";

    const pages = contentCatalog.findBy({ family: "page" });

    for (const page of pages) {
      if (!page.out) continue;

      if (page.asciidoc.attributes["page-llm-ignore"]) {
        console.log(
          `LLM Generator: Skipping page with 'page-llm-ignore' attribute: ${page.src.path}`
        );
        continue;
      }

      if (page.src.path.startsWith("modules/releases/")) {
        console.log(
          `LLM Generator: Skipping page in 'releases/' directory: ${page.src.path}`
        );
        continue;
      }

      indexContent += `\n- [${page.title}](https://docs.cerbos.dev/${page.out.path})`;

      if (page.asciidoc.attributes["page-llm-full-ignore"]) {
        console.log(
          `LLM Generator: Skipping page with 'page-llm-full-ignore' attribute: ${page.src.path}`
        );
        continue;
      }

      const plainText = nhm.translate(page.contents.toString());

      fullContent += `\n\n${page.title}\n`;
      fullContent += "====================\n";
      fullContent += plainText;
    }

    siteCatalog.addFile({
      out: { path: "llm-full.txt" }, // Output file path
      contents: Buffer.from(fullContent),
    });

    siteCatalog.addFile({
      out: { path: "llm.txt" }, // Output file path
      contents: Buffer.from(indexContent),
    });

    console.log("LLM Generator: llm.txt and llm-full.txt have been generated.");
  });
};
