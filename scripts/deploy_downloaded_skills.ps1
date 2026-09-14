# Deploy Downloaded Skills to Antigravity (.agents / .agent), Codex (.codex), and Claude (.claude)
$ErrorActionPreference = "Stop"

$workspaceRoot = (Get-Location).Path
$marketplaceRoot = Join-Path $workspaceRoot "skills_marketplace"
$linkedinRoot = Join-Path $marketplaceRoot "linkedin-skills"
$claudeAdsRoot = Join-Path $marketplaceRoot "claude-ads"

$targetSkillDirs = @(
    (Join-Path $workspaceRoot ".agents\skills"),
    (Join-Path $workspaceRoot ".agent\skills"),
    (Join-Path $env:USERPROFILE ".codex\skills"),
    (Join-Path $env:USERPROFILE ".claude\skills")
)

Write-Host "=========================================================="
Write-Host "  W1™ Multi-Agent Skills Deployment Orchestrator"
Write-Host "=========================================================="

foreach ($targetBase in $targetSkillDirs) {
    Write-Host "`n[*] Target Destination: $targetBase"
    New-Item -ItemType Directory -Force -Path $targetBase | Out-Null

    # 1. Deploy LinkedIn Master Skill
    $liMasterDest = Join-Path $targetBase "linkedin-marketing"
    New-Item -ItemType Directory -Force -Path $liMasterDest | Out-Null
    Copy-Item -Force (Join-Path $linkedinRoot "SKILL.md") (Join-Path $liMasterDest "SKILL.md")
    if (Test-Path (Join-Path $linkedinRoot "references")) {
        Copy-Item -Recurse -Force (Join-Path $linkedinRoot "references") (Join-Path $liMasterDest "references")
    }
    if (Test-Path (Join-Path $linkedinRoot "lib")) {
        Copy-Item -Recurse -Force (Join-Path $linkedinRoot "lib") (Join-Path $liMasterDest "lib")
    }
    if (Test-Path (Join-Path $linkedinRoot "scripts")) {
        Copy-Item -Recurse -Force (Join-Path $linkedinRoot "scripts") (Join-Path $liMasterDest "scripts")
    }

    # 2. Deploy LinkedIn 12 Subskills
    $liSubskills = Get-ChildItem (Join-Path $linkedinRoot "skills") -Directory
    foreach ($sub in $liSubskills) {
        $subDest = Join-Path $targetBase $sub.Name
        New-Item -ItemType Directory -Force -Path $subDest | Out-Null
        Copy-Item -Recurse -Force (Join-Path $sub.FullName "*") $subDest
        # Also ensure subskills have direct copy of references if needed
        if (Test-Path (Join-Path $linkedinRoot "references")) {
            $subRefDest = Join-Path $subDest "references"
            if (-not (Test-Path $subRefDest)) {
                Copy-Item -Recurse -Force (Join-Path $linkedinRoot "references") $subRefDest
            }
        }
    }
    Write-Host "   -> Deployed 13 LinkedIn skills (1 master + 12 subskills)"

    # 3. Deploy Claude Ads Master Skill
    $adsMasterDest = Join-Path $targetBase "ads"
    New-Item -ItemType Directory -Force -Path $adsMasterDest | Out-Null
    Copy-Item -Force (Join-Path $claudeAdsRoot "ads\SKILL.md") (Join-Path $adsMasterDest "SKILL.md")
    if (Test-Path (Join-Path $claudeAdsRoot "ads\references")) {
        Copy-Item -Recurse -Force (Join-Path $claudeAdsRoot "ads\references") (Join-Path $adsMasterDest "references")
    }
    if (Test-Path (Join-Path $claudeAdsRoot "ads\agents")) {
        Copy-Item -Recurse -Force (Join-Path $claudeAdsRoot "ads\agents") (Join-Path $adsMasterDest "agents")
    }

    # 4. Deploy Claude Ads 33 Subskills
    $adsSubskills = Get-ChildItem (Join-Path $claudeAdsRoot "skills") -Directory
    foreach ($sub in $adsSubskills) {
        $subDest = Join-Path $targetBase $sub.Name
        New-Item -ItemType Directory -Force -Path $subDest | Out-Null
        Copy-Item -Recurse -Force (Join-Path $sub.FullName "*") $subDest
    }
    Write-Host "   -> Deployed 34 Claude Ads skills (1 master + 33 subskills)"
}

# Also ensure workspace .agents and .agent have root references and lib for ../../ relative path lookups
foreach ($agentRoot in @((Join-Path $workspaceRoot ".agents"), (Join-Path $workspaceRoot ".agent"))) {
    New-Item -ItemType Directory -Force -Path $agentRoot | Out-Null
    if (Test-Path (Join-Path $linkedinRoot "references")) {
        Copy-Item -Recurse -Force (Join-Path $linkedinRoot "references") (Join-Path $agentRoot "references")
    }
    if (Test-Path (Join-Path $linkedinRoot "lib")) {
        Copy-Item -Recurse -Force (Join-Path $linkedinRoot "lib") (Join-Path $agentRoot "lib")
    }
    if (Test-Path (Join-Path $claudeAdsRoot "ads")) {
        Copy-Item -Recurse -Force (Join-Path $claudeAdsRoot "ads") (Join-Path $agentRoot "ads")
    }
}

Write-Host "`n[SUCCESS] Successfully deployed 47 skills across all target destinations!"
