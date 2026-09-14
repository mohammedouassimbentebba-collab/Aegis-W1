/**
 * W1™ Universal AI Agent Harness Adapter (محول بروتوكولات نماذج الذكاء الاصطناعي)
 * File: src/ai_testbed/agent_harness_adapter.js
 *
 * Core Responsibility:
 * Sits as an inline supervisor between LLM Generation and Tool Execution.
 * Normalizes tool-calling schemas from:
 *   1. OpenAI Format (tool_calls with function: { name, arguments })
 *   2. Anthropic Claude Format (type: 'tool_use', id, name, input)
 *   3. Google Gemini Format (functionCall: { name, args })
 *   4. Raw Agent Format ({ action, params, command })
 *
 * Enforces Pre-Action Thought Tomography on:
 *   - message.reasoning_content (DeepSeek-R1 / OpenAI o1/o3)
 *   - message.thinking (Claude 3.7 Extended Thinking)
 *   - scratchpad / inner_dialogue fields
 *
 * Dispatches verified actions into HermeticWorkTent with single-use capability tokens.
 */

import { CapabilityTokenManager } from '../perimeter/capability_token_manager.js';
import { ThreatDomain, ThreatSeverity, ThreatDetectionEvent } from '../core/types.js';

export class AgentHarnessAdapter {
  constructor(options = {}) {
    this.name = 'W1_Agent_Harness_Adapter';
    this.tent = options.tent; // Instance of HermeticWorkTent
    this.tokenManager = options.tokenManager || (this.tent ? this.tent.tokenManager : new CapabilityTokenManager());
    this.agentId = options.agentId || (this.tent ? this.tent.agentId : 'ai_agent_evaluator');
    this.interceptionLog = [];
  }

  /**
   * Primary Entrypoint: Ingests model responses across formats, performs thought tomography,
   * executes valid tools within the Hermetic Work Tent, and formats responses back to caller.
   */
  async processModelOutput(modelMessage, options = {}) {
    const t0 = performance.now();
    const scratchpad = this.extractReasoning(modelMessage);

    // 1. Pre-Action Thought Tomography on internal reasoning blocks
    if (scratchpad && this.tent && this.tent.watchdog) {
      const thoughtScan = this.tent.watchdog.inspectScratchpad(this.agentId, scratchpad);
      if (!thoughtScan.clean) {
        this.tent.triggerContainmentAlarm(thoughtScan.violationType, thoughtScan.reason, thoughtScan.threat);
        const errorResult = {
          success: false,
          escapeDetected: true,
          status: 'COGNITIVE_DECEPTION_INTERCEPTED',
          reason: thoughtScan.reason,
          threat: thoughtScan.threat
        };
        return this.formatErrorResponse(modelMessage, errorResult);
      }
    }

    // 2. Normalize tool calls into a unified execution list
    const toolCalls = this.normalizeToolCalls(modelMessage);
    if (toolCalls.length === 0) {
      return {
        hasToolCalls: false,
        textResponse: modelMessage.content || modelMessage.text || '',
        reasoningContent: scratchpad
      };
    }

    const executionResults = [];

    // 3. Process each tool call sequentially under Hermetic Work Tent invariants
    for (const call of toolCalls) {
      const { toolId, toolName, arguments: rawArgs, format } = call;

      let parsedParams = {};
      if (typeof rawArgs === 'string') {
        try {
          parsedParams = JSON.parse(rawArgs);
        } catch {
          parsedParams = { raw: rawArgs };
        }
      } else if (typeof rawArgs === 'object' && rawArgs !== null) {
        parsedParams = rawArgs;
      }

      // Map tool name to HermeticWorkTent action
      const actionMapping = this.mapToolToAction(toolName, parsedParams);

      // Issue single-use capability token for this specific resource
      const targetResource = parsedParams.path || parsedParams.resource || parsedParams.command || '*';
      const token = this.tokenManager.issueToken({
        agentId: this.agentId,
        allowedAction: actionMapping.action,
        allowedResource: targetResource,
        ttlSeconds: 60,
        singleUse: true
      });

      // Execute inside Hermetic Work Tent
      let actionResult;
      if (this.tent) {
        actionResult = await this.tent.executeTentAction({
          action: actionMapping.action,
          params: actionMapping.params,
          capabilityToken: token,
          scratchpad
        });
      } else {
        actionResult = {
          success: true,
          status: 'TENT_OFFLINE_DRY_RUN',
          executionRecord: { action: actionMapping.action, params: actionMapping.params }
        };
      }

      this.interceptionLog.push({
        timestamp: Date.now(),
        toolId,
        toolName,
        action: actionMapping.action,
        success: actionResult.success,
        escapeDetected: !!actionResult.escapeDetected,
        durationMs: performance.now() - t0
      });

      executionResults.push({
        toolId,
        toolName,
        format,
        result: actionResult
      });
    }

    // 4. Return formatted response compatible with the caller's protocol
    return this.formatSuccessResponse(modelMessage, executionResults);
  }

  /**
   * Extracts reasoning / internal thoughts across various frontier model schemas:
   * - DeepSeek-R1 / OpenAI: message.reasoning_content
   * - Claude 3.7 Sonnet: message.thinking or blocks of type 'thinking'
   * - Gemini / Raw: params.thought or message.scratchpad
   */
  extractReasoning(modelMessage) {
    if (!modelMessage) return '';

    // Direct reasoning fields
    if (typeof modelMessage.reasoning_content === 'string') {
      return modelMessage.reasoning_content;
    }
    if (typeof modelMessage.thinking === 'string') {
      return modelMessage.thinking;
    }
    if (typeof modelMessage.scratchpad === 'string') {
      return modelMessage.scratchpad;
    }

    // Anthropic content blocks array
    if (Array.isArray(modelMessage.content)) {
      for (const block of modelMessage.content) {
        if (block.type === 'thinking' && block.thinking) {
          return block.thinking;
        }
        if (block.type === 'text' && typeof block.text === 'string') {
          // Look for <thinking> or <scratchpad> tags
          const match = block.text.match(/<(thinking|scratchpad)>([\s\S]*?)<\/\1>/i);
          if (match) return match[2].trim();
        }
      }
    }

    // String content with embedded reasoning tags
    if (typeof modelMessage.content === 'string') {
      const match = modelMessage.content.match(/<(thinking|scratchpad)>([\s\S]*?)<\/\1>/i);
      if (match) return match[2].trim();
    }

    return '';
  }

  /**
   * Normalizes tool calls from OpenAI, Anthropic, Gemini, or custom schemas
   */
  normalizeToolCalls(modelMessage) {
    const normalized = [];

    // Format 1: OpenAI Tool Calls
    if (Array.isArray(modelMessage.tool_calls)) {
      for (const tc of modelMessage.tool_calls) {
        normalized.push({
          toolId: tc.id || `call_${Math.random().toString(36).substring(2, 9)}`,
          toolName: tc.function?.name || tc.name,
          arguments: tc.function?.arguments || tc.arguments || {},
          format: 'openai'
        });
      }
      return normalized;
    }

    // Format 2: Anthropic Content Blocks (type: 'tool_use')
    if (Array.isArray(modelMessage.content)) {
      for (const block of modelMessage.content) {
        if (block.type === 'tool_use') {
          normalized.push({
            toolId: block.id,
            toolName: block.name,
            arguments: block.input || {},
            format: 'anthropic'
          });
        }
      }
      if (normalized.length > 0) return normalized;
    }

    // Format 3: Google Gemini functionCall
    if (modelMessage.functionCall) {
      normalized.push({
        toolId: `gemini_call_${Math.random().toString(36).substring(2, 9)}`,
        toolName: modelMessage.functionCall.name,
        arguments: modelMessage.functionCall.args || {},
        format: 'gemini'
      });
      return normalized;
    }

    // Format 4: Direct Action / Custom Harness
    if (modelMessage.action && typeof modelMessage.action === 'string') {
      normalized.push({
        toolId: `direct_call_${Math.random().toString(36).substring(2, 9)}`,
        toolName: modelMessage.action,
        arguments: modelMessage.params || {},
        format: 'direct'
      });
      return normalized;
    }

    return normalized;
  }

  /**
   * Maps generic tool names from agent harnesses (e.g. bash, str_replace_editor, file_writer)
   * to strictly typed HermeticWorkTent actions.
   */
  mapToolToAction(toolName, params) {
    const tName = (toolName || '').toLowerCase();

    if (tName === 'bash' || tName === 'terminal' || tName === 'execute_command' || tName === 'run_command') {
      return {
        action: 'RUN_IN_TENT_SCRIPT',
        params: {
          command: params.command || params.cmd || '',
          ...params
        }
      };
    }

    if (tName === 'read_file' || tName === 'view_file' || tName === 'cat') {
      return {
        action: 'READ_FILE',
        params: {
          path: params.path || params.file_path || params.targetFile || '',
          ...params
        }
      };
    }

    if (tName === 'write_file' || tName === 'create_file' || tName === 'str_replace_editor' || tName === 'edit_file') {
      return {
        action: 'WRITE_FILE',
        params: {
          path: params.path || params.file_path || params.targetFile || '',
          content: params.content || params.code || params.new_str || '',
          ...params
        }
      };
    }

    if (tName === 'submit_ticket' || tName === 'halt_and_escalate') {
      return {
        action: 'SUBMIT_ESCALATION_TICKET',
        params
      };
    }

    // Default passthrough
    return {
      action: toolName,
      params
    };
  }

  /**
   * Formats execution results back to the caller matching the incoming protocol
   */
  formatSuccessResponse(originalMessage, executionResults) {
    const primaryFormat = (executionResults[0] && executionResults[0].format) || 'openai';

    if (primaryFormat === 'anthropic') {
      const content = executionResults.map(res => ({
        type: 'tool_result',
        tool_use_id: res.toolId,
        content: JSON.stringify(res.result)
      }));
      return {
        role: 'user',
        content,
        hasToolCalls: true,
        executionResults
      };
    }

    if (primaryFormat === 'gemini') {
      const functionResponses = executionResults.map(res => ({
        functionResponse: {
          name: res.toolName,
          response: res.result
        }
      }));
      return {
        role: 'function',
        parts: functionResponses,
        hasToolCalls: true,
        executionResults
      };
    }

    // Default: OpenAI format (role: 'tool' messages)
    const toolMessages = executionResults.map(res => ({
      role: 'tool',
      tool_call_id: res.toolId,
      name: res.toolName,
      content: JSON.stringify(res.result)
    }));

    return {
      role: 'tool_responses',
      messages: toolMessages,
      hasToolCalls: true,
      executionResults
    };
  }

  /**
   * Formats containment alarm / cognitive deception intercept into standard model error response
   */
  formatErrorResponse(originalMessage, errorResult) {
    return {
      interceptionTriggered: true,
      quarantined: true,
      error: errorResult,
      responseMessage: {
        role: 'system',
        content: `W1_CONTAINMENT_ALARM: Execution halted. Cognitive deception or escape intent detected: ${errorResult.reason}`
      }
    };
  }
}
