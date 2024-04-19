import {
  RuntimeModule,
  runtimeMethod,
  state,
  runtimeModule,
} from "@proto-kit/module";
import { StateMap, assert } from "@proto-kit/protocol";
import { Bool, Field, Struct, Provable, UInt64 } from "o1js";

export class SecurityCode extends Struct({
  char0: Field,
  char1: Field,
}) {}

export class AgentId extends UInt64 {}

export class Message extends Struct({
  messageNumber: UInt64,
  agentId: AgentId,
  body: Provable.Array(Field, 12),
  securityCode: SecurityCode,
}) {}

export class Agent extends Struct({
  agentId: AgentId,
  lastMessage: UInt64,
  securityCode: SecurityCode,
}) {}

type SpyMasterConfig = Record<string, never>;

@runtimeModule()
export class SpyMaster extends RuntimeModule<SpyMasterConfig> {
  @state() public agents = StateMap.from<AgentId, Agent>(AgentId, Agent);

  @runtimeMethod()
  public addAgent(agentId: AgentId, securityCode: SecurityCode) {
    this.agents.set(
      agentId,
      new Agent({
        agentId: agentId,
        lastMessage: UInt64.from(0),
        securityCode: securityCode,
      }),
    );
  }

  setLastMessage(agentId: AgentId, lastMessage: UInt64) {
    const agent = this.agents.get(agentId).value;
    const newAgent = new Agent({
      agentId: agent.agentId,
      lastMessage: lastMessage,
      securityCode: agent.securityCode,
    });
    this.agents.set(agentId, newAgent);
  }

  @runtimeMethod()
  public processMessage(message: Message) {
    const agent = this.agents.get(message.agentId).value;

    assert(
      Bool.and(
        agent.securityCode.char0.equals(message.securityCode.char0),
        agent.securityCode.char1.equals(message.securityCode.char1),
      ),
      "Security code does not match",
    );
    assert(
      UInt64.from(message.body.length).equals(UInt64.from(12)),
      "Message length is not 12 characters",
    );
    assert(
      message.messageNumber.greaterThan(agent.lastMessage),
      "Message number is not greater than the last message number",
    );

    this.setLastMessage(message.agentId, message.messageNumber);
  }
}
