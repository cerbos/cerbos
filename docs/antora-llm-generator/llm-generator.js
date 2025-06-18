"use strict";

const { NodeHtmlMarkdown } = require("node-html-markdown");

const nhm = new NodeHtmlMarkdown();

/**
 * An Antora extension that generates a single text file containing all the
 * content of the site, suitable for consumption by an LLM.
 */
module.exports.register = function (context) {
  const logger = context.getLogger("antora-llm-generator");
  const { playbook } = context.getVariables(); // playbook is available as soon as Antora starts
  const siteTitle = playbook.site?.title || "Documentation";
  const siteUrl = playbook.site?.url;

  const skipPaths = context.skipPaths || [];

  context.on("navigationBuilt", ({ contentCatalog, siteCatalog }) => {
    logger.info("LLM Generator: Assembling content for LLM text files.");

    let indexContent = `# ${siteTitle}\n\n`;
    let fullContent = "";

    const pages = contentCatalog.findBy({ family: "page" });

    for (const page of pages) {
      if (!page.out) continue;

      if (page.asciidoc.attributes["page-llm-ignore"]) {
        logger.warn(
          `LLM Generator: Skipping page with 'page-llm-ignore' attribute: ${page.src.path}`
        );
        continue;
      }

      if (skipPaths.some((path) => page.src.path.startsWith(path))) {
        logger.warn(
          `LLM Generator: Skipping page in 'releases/' directory: ${page.src.path}`
        );
        continue;
      }

      indexContent += `\n- [${page.title}](${siteUrl}/${page.out.path})`;

      if (page.asciidoc.attributes["page-llm-full-ignore"]) {
        logger.warn(
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

    logger.info("LLM Generator: llm.txt and llm-full.txt have been generated.");
  });
};
