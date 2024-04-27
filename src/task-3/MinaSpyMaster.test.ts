import "reflect-metadata";
import { TestingAppChain } from "@proto-kit/sdk";
import { Field, PrivateKey, MerkleMap, Poseidon, Bool, UInt64 } from "o1js";
import { SpyMaster, Agent, AgentId, Message, SecurityCode } from "./MinaSpyMaster";
import { Balances } from "./Balances";

describe("MinaSpyMaster", () => {
  let appChain: TestingAppChain<{
    SpyMaster: typeof SpyMaster;
    Balances: typeof Balances;
  }>;

  let spymaster: SpyMaster;
  let balances: Balances;

  const aliceKey = PrivateKey.random();
  const alice = aliceKey.toPublicKey(); // Alice is the spy master

  const map = new MerkleMap();
  const key = Poseidon.hash(alice.toFields());
  map.set(key, Bool(true).toField()); // set alice's balance to 1

  beforeAll(async () => {
    appChain = TestingAppChain.fromRuntime({
      modules: { SpyMaster: SpyMaster, Balances: Balances, },
      config: { SpyMaster: {}, Balances: {}, },
    });

    appChain.setSigner(aliceKey);
    await appChain.start();
    spymaster = appChain.runtime.resolve("SpyMaster");
    balances = appChain.runtime.resolve("Balances");
  });

  it("adding an agent", async () => {
    const txn = appChain.transaction(alice, () => {
      spymaster.addAgent(AgentId.from(0), new SecurityCode({ char0: new Field(97), char1: new Field(98) }),);
    });
    await txn.sign();
    await txn.send();
    await appChain.produceBlock();

    const agent = await appChain.query.runtime.SpyMaster.agents.get(AgentId.from(0),);
    expect(agent).toEqual(
      new Agent({
        agentId: AgentId.from(0), lastMessage: UInt64.from(0), securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      }),
    );
  });

  it("process message & update account state", async () => {
    const messageStr = "123456789xyz";
    const asciiFields = [];
    for (var i = 0; i < messageStr.length; i++) {
      asciiFields.push(Field(messageStr.charCodeAt(i)));
    }
    const message = new Message({messageNumber: UInt64.from(1),agentId: AgentId.from(0),body: asciiFields,securityCode: new SecurityCode({ char0: new Field(97), char1: new Field(98),}),});
    const txn = appChain.transaction(alice, () => {spymaster.processMessage(message)});

    await txn.sign();
    await txn.send();
    let block = await appChain.produceBlock();

    expect(block).toBeTruthy();
    expect(block?.txs[0]?.status).toBeTruthy();

    const agent = await appChain.query.runtime.SpyMaster.agents.get(AgentId.from(0));
    if (agent) expect(agent.lastMessage).toEqual(UInt64.from(1));
  });

  describe("When Cases fail", () => {
    it("When message is longer than 12 characters", async () => {
      const messageStr = "123456789xyzc"; // 13 characters
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({
        messageNumber: UInt64.from(1),
        agentId: AgentId.from(0),
        body: asciiFields,
        securityCode: new SecurityCode({ char0: new Field(97), char1: new Field(98)}),
      });

      const txn = appChain.transaction(alice, () => {spymaster.processMessage(message)});
      await txn.sign();
      await txn.send();
      let block = await appChain.produceBlock();

      expect(block).toBeTruthy();
      expect(block?.txs[0]?.status).toBeFalsy();
      expect(block?.txs[0]?.statusMessage).toEqual(
        "Message length is not 12 characters",
      );
    });

    it("When message is shorter than 12 characters", async () => {
      const messageStr = "123456789xy"; // 11 characters
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }

      const message = new Message({messageNumber: UInt64.from(1),agentId: AgentId.from(0), body: asciiFields,securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      });

      const txn = appChain.transaction(alice, () => {spymaster.processMessage(message);});
      await txn.sign();
      await txn.send();
      let block = await appChain.produceBlock();

      expect(block).toBeTruthy();

      expect(block?.txs[0]?.status).toBeFalsy();
      expect(block?.txs[0]?.statusMessage).toEqual(
        "Message length is not 12 characters",
      );
    });

    it("When the security code does not match", async () => {
      const messageStr = "123456789xyz";
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({messageNumber: UInt64.from(1), agentId: AgentId.from(0), body: asciiFields, securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(99),
        }),
      });

      const txn = appChain.transaction(alice, () => {spymaster.processMessage(message);});
      await txn.sign();
      await txn.send();
      let block = await appChain.produceBlock();

      expect(block).toBeTruthy();
      expect(block?.txs[0]?.status).toBeFalsy();
      expect(block?.txs[0]?.statusMessage).toEqual(
        "Security code does not match",
      );
    });

    it("When the message number is not greater than the last message number - fail", async () => {
      const messageStr = "123456789xyz";
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({ messageNumber: UInt64.from(0), agentId: AgentId.from(0),body: asciiFields, securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      });

      const txn = appChain.transaction(alice, () => { spymaster.processMessage(message);});
      await txn.sign();
      await txn.send();
      let block = await appChain.produceBlock();

      expect(block).toBeTruthy();
      expect(block?.txs[0]?.status).toBeFalsy();
      expect(block?.txs[0]?.statusMessage).toEqual(
        "Message no. is not greater than the last message no.",
      );
    });
  });
});
