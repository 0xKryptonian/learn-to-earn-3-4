import "reflect-metadata";
import { TestingAppChain } from "@proto-kit/sdk";
import { SpyMaster, Agent, AgentId, Message, SecurityCode } from "./SpyMaster";
import { Field, PrivateKey, MerkleMap, Poseidon, Bool, UInt64 } from "o1js";
import { Balances } from "./Balances";

describe("SpyMaster", () => {
  let appChain: TestingAppChain<{
    SpyMaster: typeof SpyMaster;
    Balances: typeof Balances;
  }>;

  let spymaster: SpyMaster;
  let balances: Balances;

  const aliceKey = PrivateKey.random();
  const alice = aliceKey.toPublicKey();

  const map = new MerkleMap();
  const key = Poseidon.hash(alice.toFields());
  map.set(key, Bool(true).toField());

  beforeAll(async () => {
    appChain = TestingAppChain.fromRuntime({
      modules: {
        SpyMaster: SpyMaster,
        Balances: Balances,
      },
      config: {
        SpyMaster: {},
        Balances: {},
      },
    });

    appChain.setSigner(aliceKey);

    await appChain.start();

    spymaster = appChain.runtime.resolve("SpyMaster");
    balances = appChain.runtime.resolve("Balances");
  });

  it("should add an agent", async () => {
    const tx = appChain.transaction(alice, () => {
      spymaster.addAgent(
        AgentId.from(0),
        new SecurityCode({ char0: new Field(97), char1: new Field(98) }),
      );
    });
    await tx.sign();
    await tx.send();
    await appChain.produceBlock();

    const agent = await appChain.query.runtime.SpyMaster.agents.get(
      AgentId.from(0),
    );
    expect(agent).toEqual(
      new Agent({
        agentId: AgentId.from(0),
        lastMessage: UInt64.from(0),
        securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      }),
    );
  });

  it("should process a message and update the account state", async () => {
    const messageStr = "0123456789ab";
    const asciiFields = [];
    for (var i = 0; i < messageStr.length; i++) {
      asciiFields.push(Field(messageStr.charCodeAt(i)));
    }
    const message = new Message({
      messageNumber: UInt64.from(1),
      agentId: AgentId.from(0),
      body: asciiFields,
      securityCode: new SecurityCode({
        char0: new Field(97),
        char1: new Field(98),
      }),
    });
    const tx = appChain.transaction(alice, () => {
      spymaster.processMessage(message);
    });

    await tx.sign();
    await tx.send();

    let block = await appChain.produceBlock();

    expect(block).toBeTruthy();
    expect(block?.txs[0]?.status).toBeTruthy();

    const agent = await appChain.query.runtime.SpyMaster.agents.get(
      AgentId.from(0),
    );

    if (agent) expect(agent.lastMessage).toEqual(UInt64.from(1));
  });

  describe("Fail Cases", () => {
    it("message is longer than 12 characters long", async () => {
      const messageStr = "0123456789abc"; // 13 characters
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({
        messageNumber: UInt64.from(1),
        agentId: AgentId.from(0),
        body: asciiFields,
        securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      });
      const tx = appChain.transaction(alice, () => {
        spymaster.processMessage(message);
      });

      await tx.sign();
      await tx.send();

      let block = await appChain.produceBlock();

      expect(block).toBeTruthy();

      expect(block?.txs[0]?.status).toBeFalsy();
      expect(block?.txs[0]?.statusMessage).toEqual(
        "Message length is not 12 characters",
      );
    });

    it("message is shorter than 12 characters long", async () => {
      const messageStr = "0123456789a"; // 11 characters
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({
        messageNumber: UInt64.from(1),
        agentId: AgentId.from(0),
        body: asciiFields,
        securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      });
      const tx = appChain.transaction(alice, () => {
        spymaster.processMessage(message);
      });

      await tx.sign();
      await tx.send();

      let block = await appChain.produceBlock();

      expect(block).toBeTruthy();

      expect(block?.txs[0]?.status).toBeFalsy();
      expect(block?.txs[0]?.statusMessage).toEqual(
        "Message length is not 12 characters",
      );
    });

    it("Should fail when the security code does not match", async () => {
      const messageStr = "0123456789ab";
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({
        messageNumber: UInt64.from(1),
        agentId: AgentId.from(0),
        body: asciiFields,
        securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(99), // changed from 98 to 99
        }),
      });
      const tx = appChain.transaction(alice, () => {
        spymaster.processMessage(message);
      });

      await tx.sign();
      await tx.send();

      let block = await appChain.produceBlock();

      expect(block).toBeTruthy();
      expect(block?.txs[0]?.status).toBeFalsy();
      expect(block?.txs[0]?.statusMessage).toEqual(
        "Security code does not match",
      );
    });

    it("Should fail when the message number is not greater than the last message number", async () => {
      const messageStr = "0123456789ab";
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({
        messageNumber: UInt64.from(0), // changed from 1 to 0
        agentId: AgentId.from(0),
        body: asciiFields,
        securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      });
      const tx = appChain.transaction(alice, () => {
        spymaster.processMessage(message);
      });

      await tx.sign();
      await tx.send();

      let block = await appChain.produceBlock();

      expect(block).toBeTruthy();
      expect(block?.txs[0]?.status).toBeFalsy();
      expect(block?.txs[0]?.statusMessage).toEqual(
        "Message number is not greater than the last message number",
      );
    });
  });
});
