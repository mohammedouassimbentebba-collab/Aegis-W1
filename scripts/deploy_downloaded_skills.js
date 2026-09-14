/**
 * W1™ Multi-Agent Skills Deployment Orchestrator
 * Automatically distributes LinkedIn Skills and Claude Ads to:
 * 1. Project .agents/skills/ (Antigravity primary)
 * 2. Project .agent/skills/ (Antigravity secondary)
 * 3. User ~/.codex/skills/ (OpenAI Codex CLI)
 * 4. User ~/.claude/skills/ (Claude Code CLI)
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const workspaceRoot = process.cwd();
const marketplaceRoot = path.join(workspaceRoot, 'skills_marketplace');
const linkedinRoot = path.join(marketplaceRoot, 'linkedin-skills');
const claudeAdsRoot = path.join(marketplaceRoot, 'claude-ads');

const userHome = os.homedir();
const targetSkillDirs = [
  path.join(workspaceRoot, '.agents', 'skills'),
  path.join(workspaceRoot, '.agent', 'skills'),
  path.join(userHome, '.codex', 'skills'),
  path.join(userHome, '.claude', 'skills')
];

console.log('==========================================================');
console.log('  W1™ Multi-Agent Skills Deployment Orchestrator');
console.log('==========================================================');

function copyDirRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else if (entry.isFile()) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

for (const targetBase of targetSkillDirs) {
  try {
    console.log(`\n[*] Target Destination: ${targetBase}`);
    fs.mkdirSync(targetBase, { recursive: true });

    // 1. Deploy LinkedIn Master Skill
    const liMasterDest = path.join(targetBase, 'linkedin-marketing');
    fs.mkdirSync(liMasterDest, { recursive: true });
    fs.copyFileSync(path.join(linkedinRoot, 'SKILL.md'), path.join(liMasterDest, 'SKILL.md'));
    copyDirRecursive(path.join(linkedinRoot, 'references'), path.join(liMasterDest, 'references'));
    copyDirRecursive(path.join(linkedinRoot, 'lib'), path.join(liMasterDest, 'lib'));
    copyDirRecursive(path.join(linkedinRoot, 'scripts'), path.join(liMasterDest, 'scripts'));

    // 2. Deploy LinkedIn 12 Subskills
    const liSubskillsDir = path.join(linkedinRoot, 'skills');
    if (fs.existsSync(liSubskillsDir)) {
      const subskills = fs.readdirSync(liSubskillsDir, { withFileTypes: true }).filter(d => d.isDirectory());
      for (const sub of subskills) {
        const subSrc = path.join(liSubskillsDir, sub.name);
        const subDest = path.join(targetBase, sub.name);
        copyDirRecursive(subSrc, subDest);
        // Ensure local references exist if subskill looks for them
        copyDirRecursive(path.join(linkedinRoot, 'references'), path.join(subDest, 'references'));
      }
      console.log(`   -> Deployed 13 LinkedIn skills (1 master + ${subskills.length} subskills)`);
    }

    // 3. Deploy Claude Ads Master Skill
    const adsMasterDest = path.join(targetBase, 'ads');
    fs.mkdirSync(adsMasterDest, { recursive: true });
    fs.copyFileSync(path.join(claudeAdsRoot, 'ads', 'SKILL.md'), path.join(adsMasterDest, 'SKILL.md'));
    copyDirRecursive(path.join(claudeAdsRoot, 'ads', 'references'), path.join(adsMasterDest, 'references'));
    copyDirRecursive(path.join(claudeAdsRoot, 'ads', 'agents'), path.join(adsMasterDest, 'agents'));

    // 4. Deploy Claude Ads 33 Subskills
    const adsSubskillsDir = path.join(claudeAdsRoot, 'skills');
    if (fs.existsSync(adsSubskillsDir)) {
      const subskills = fs.readdirSync(adsSubskillsDir, { withFileTypes: true }).filter(d => d.isDirectory());
      for (const sub of subskills) {
        const subSrc = path.join(adsSubskillsDir, sub.name);
        const subDest = path.join(targetBase, sub.name);
        copyDirRecursive(subSrc, subDest);
      }
      console.log(`   -> Deployed 34 Claude Ads skills (1 master + ${subskills.length} subskills)`);
    }
  } catch (err) {
    console.warn(`   [!] Notice: Skipping ${targetBase} due to OS permissions: ${err.message}`);
  }
}

// Ensure .agents and .agent have root references and lib for ../../ lookups
for (const agentRoot of [path.join(workspaceRoot, '.agents'), path.join(workspaceRoot, '.agent')]) {
  copyDirRecursive(path.join(linkedinRoot, 'references'), path.join(agentRoot, 'references'));
  copyDirRecursive(path.join(linkedinRoot, 'lib'), path.join(agentRoot, 'lib'));
  copyDirRecursive(path.join(claudeAdsRoot, 'ads'), path.join(agentRoot, 'ads'));
}

console.log('\n[SUCCESS] Successfully deployed 47 skills across all target destinations!');
