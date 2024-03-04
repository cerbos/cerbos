#!/usr/bin/env node

const { platform: os, arch } = process;
const currentPlatform = `${os}-${arch}`;
const supportedPlatforms = {{ .SupportedPlatforms }};

if (!supportedPlatforms.includes(currentPlatform)) {
  throw new Error(`Your current operating system (${os}) and architecture (${arch}) is not supported by the {{ .Name }} npm package.

The following combinations are supported:
${supportedPlatforms.map((platform) => `- ${platform}`).join("\n")}

Maybe try running in a container instead?
https://docs.cerbos.dev/cerbos/latest/installation/container`);
}

const binaryPackage = `@cerbos/{{ .Name }}-${os}-${arch}`;

const binaryPath = (() => {
  try {
    return require.resolve(binaryPackage);
  } catch (error) {
    throw new Error(`Couldn't find the "${binaryPackage}" package.

Make sure optional dependencies are installed.`, { cause: error });
  }
})();

require("child_process").execFileSync(binaryPath, process.argv.slice(2), { stdio: "inherit" });
