import installScripts from "./install-scripts.js";
import networkAccess from "./network-access.js";
import filesystemAccess from "./filesystem-access.js";
import codeExecution from "./code-execution.js";
import obfuscation from "./obfuscation.js";
import dataExfiltration from "./data-exfiltration.js";
import hiddenChars from "./hidden-chars.js";

export const rules = [
  installScripts,
  networkAccess,
  filesystemAccess,
  codeExecution,
  obfuscation,
  dataExfiltration,
  hiddenChars,
];

export function getRuleById(id) {
  return rules.find((r) => r.id === id);
}

export function getEnabledRules(config) {
  const ruleMap = {
    installScripts: "install-scripts",
    networkAccess: "network-access",
    filesystemAccess: "filesystem-access",
    codeExecution: "code-execution",
    obfuscation: "obfuscation",
    dataExfiltration: "data-exfiltration",
    hiddenChars: "hidden-chars",
  };

  return rules.filter((rule) => {
    const configKey = Object.entries(ruleMap).find(
      ([, id]) => id === rule.id,
    )?.[0];
    return configKey ? config.isRuleEnabled(configKey) : true;
  });
}
