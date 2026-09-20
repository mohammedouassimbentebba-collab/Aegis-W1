/**
 * W1™ AI Safety Fortress & Cognitive Dome (حصن وقبة الدفاع الإدراكي لسلامة الذكاء الاصطناعي)
 *
 * Grounded in DO-178C Level A avionics safety and military defense-in-depth doctrine.
 */

export { DeterministicKernel } from './core/deterministic_kernel.js';
export { CryptographicDAG, DAGNode } from './core/cryptographic_dag.js';
export { StaticLinter } from './core/static_linter.js';
export {
  DefenseCondition,
  ThreatDomain,
  ThreatSeverity,
  AgentStatus,
  ActionType,
  ThreatDetectionEvent,
  InterceptionResult
} from './core/types.js';

export { AirDefenseInterceptor } from './defense_grid/air_defense_interceptor.js';
export { EarlyWarningRadar } from './defense_grid/early_warning_radar.js';
export { DeepSubmarineSonar } from './defense_grid/deep_submarine_sonar.js';
export { ByzantineCounterIntel } from './defense_grid/byzantine_counter_intel.js';

export { CapabilityTokenManager } from './perimeter/capability_token_manager.js';
export { OSFirewallShield } from './perimeter/os_firewall_shield.js';

export { FortressCommander } from './orchestrator/fortress_commander.js';
export { WarningBroadcastSystem } from './orchestrator/warning_broadcast_system.js';

// Anti-Stealth Radar & Multi-Static Mesh
export { VHFUHFStealthRadar, MultiStaticRadarMesh } from './defense_grid/vhf_uhf_anti_stealth_radar.js';

// Hermetic Work Tent & Anti-Escape Enclave
export { HermeticWorkTent } from './enclave/hermetic_work_tent.js';
export { AntiEscapeWatchdog } from './enclave/anti_escape_watchdog.js';
export { ImmutableTestVault } from './enclave/immutable_test_vault.js';

// AI Testbed Gateway, Container Isolation & Live Proxy
export { AiTestbedGateway } from './ai_testbed/ai_testbed_gateway.js';
export { ContainerIsolationEngine } from './ai_testbed/container_isolation_engine.js';
export { LiveAIFirewallProxy } from './perimeter/live_firewall_proxy.js';

// Silicon & Chip Hardware MMU Security Layer
export { ChipHardwareSecurityLayer } from './core/chip_hardware_security_layer.js';

// Declarative Vulnerability Scanner & Zero-Day Detection Suite
export { NucleiTemplateEngine, Severity, BUILTIN_TEMPLATES } from './vulnerability_scanner/nuclei_template_engine.js';
export { ZeroDayDetector, ZeroDayThreatLevel } from './vulnerability_scanner/zero_day_detector.js';
export { CVEKnowledgeBase, CVE_ENTRIES } from './vulnerability_scanner/cve_knowledge_base.js';
export { AgentSecurityTrainer, TRAINING_MODULES } from './vulnerability_scanner/agent_security_trainer.js';


