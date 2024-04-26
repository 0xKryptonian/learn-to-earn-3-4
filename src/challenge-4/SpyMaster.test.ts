import "reflect-metadata";
import { TestingAppChain } from "@proto-kit/sdk";
import {
  ExtendedSpyMaster,
  Agent,
  AgentId,
  Message,
  SecurityCode,
  PrivateMessage,
} from "./SpyMaster";
import { Field, PrivateKey, MerkleMap, Poseidon, Bool, UInt64 } from "o1js";
import { Balances } from "./Balances";

describe("SpyMaster", () => {
  let appChain: TestingAppChain<{
    ExtendedSpyMaster: typeof ExtendedSpyMaster;
    Balances: typeof Balances;
  }>;
  let spymaster: ExtendedSpyMaster;
  let balances: Balances;

  const aliceKey = PrivateKey.random();
  const alice = aliceKey.toPublicKey();

  const map = new MerkleMap();
  const key = Poseidon.hash(alice.toFields());
  map.set(key, Bool(true).toField());

  beforeAll(async () => {
    appChain = TestingAppChain.fromRuntime({
      modules: {
        ExtendedSpyMaster: ExtendedSpyMaster,
        Balances: Balances,
      },
      config: {
        ExtendedSpyMaster: {},
        Balances: {},
      },
    });

    appChain.setSigner(aliceKey);

    await appChain.start();

    spymaster = appChain.runtime.resolve("ExtendedSpyMaster");
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

    const agent = await appChain.query.runtime.ExtendedSpyMaster.agents.get(
      AgentId.from(0),
    );
    expect(agent?.agentId).toEqual(AgentId.from(0));
    expect(agent?.lastMessage).toEqual(UInt64.from(0));
    expect(agent?.securityCode.char0).toEqual(new Field(97));
    expect(agent?.securityCode.char1).toEqual(new Field(98));
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
    // Generate the proof of message validity
    await PrivateMessage.compile();
    const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get(
      AgentId.from(0),
    )) as Agent;
    const privateMessageProof = await PrivateMessage.process(agent, message);

    const tx = appChain.transaction(alice, () => {
      spymaster.setLastMessage(agent.agentId, privateMessageProof);
    });

    await tx.sign();
    await tx.send();

    let block = await appChain.produceBlock();

    expect(block).toBeTruthy();
    expect(block?.txs[0]?.status).toBeTruthy();

    const new_agent = await appChain.query.runtime.ExtendedSpyMaster.agents.get(
      AgentId.from(0),
    );

    if (new_agent) {
      expect(new_agent.lastMessage).toEqual(UInt64.from(1));
    }
  }, 60000);

  it("should get the state details for a particular block height", async () => {
    const blockHeight = UInt64.from(2);
    const agentId =
      await appChain.query.runtime.ExtendedSpyMaster.blockHeights.get(
        blockHeight,
      );
    expect(agentId).toBeDefined();
    if (agentId !== undefined) {
      const agent =
        await appChain.query.runtime.ExtendedSpyMaster.agentToBlockInfo.get(
          agentId,
        );

      const blockInfo =
        await appChain.query.runtime.ExtendedSpyMaster.agentToBlockInfo.get(
          agentId,
        );

      expect(agent).toBeDefined();
      expect(blockInfo).toBeDefined();

      expect(blockInfo!.blockHeight).toEqual(blockHeight);
      expect(blockInfo!.transactionSender).toEqual(alice);
      expect(blockInfo!.senderNonce).toEqual(UInt64.from(0));
    }
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
      // Generate the proof of message validity
      await PrivateMessage.compile();
      const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get(
        AgentId.from(0),
      )) as Agent;
      expect(() =>
        PrivateMessage.process(agent, message),
      ).rejects.toThrowError();
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
      // Generate the proof of message validity
      await PrivateMessage.compile();
      const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get(
        AgentId.from(0),
      )) as Agent;
      expect(() =>
        PrivateMessage.process(agent, message),
      ).rejects.toThrowError();
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
      // Generate the proof of message validity
      await PrivateMessage.compile();
      const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get(
        AgentId.from(0),
      )) as Agent;
      expect(() => PrivateMessage.process(agent, message)).rejects.toThrowError(
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
      // Generate the proof of message validity
      await PrivateMessage.compile();
      const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get(
        AgentId.from(0),
      )) as Agent;
      expect(() => PrivateMessage.process(agent, message)).rejects.toThrowError(
        "Message number is not greater than the agent's last message",
      );
    });
  });
});

