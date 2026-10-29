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

function run(...args) {
  const { spawnSync } = require("child_process");

  const { status, signal, error } = spawnSync(binaryPath, args, { stdio: "inherit" });

  if (error) {
    throw error;
  }

  if (status !== null) {
    process.exit(status);
  }

  if (signal !== null) {
    const { constants } = require("os");
    const signalNumber = constants.signals[signal] ?? 127;
    process.exit(128 + signalNumber);
  }

  process.exit(255);
}

module.exports = { binaryPath, run };
