import "reflect-metadata";
import { TestingAppChain } from "@proto-kit/sdk";
import { Field, PrivateKey, MerkleMap, Poseidon, Bool, UInt64 } from "o1js";
import { Balances } from "../task-3/Balances";
import { ExtendedSpyMaster,Agent,AgentId,Message,SecurityCode,PrivateMessage,} from "./MinaSpyMaster";

describe("MinaSpyMaster", () => {
  let appChain: TestingAppChain<{ ExtendedSpyMaster: typeof ExtendedSpyMaster;Balances: typeof Balances }>;
  let spymaster: ExtendedSpyMaster;
  let balances: Balances;
  const aliceKey = PrivateKey.random();  
  const alice = aliceKey.toPublicKey();

  const map = new MerkleMap(); 
  const key = Poseidon.hash(alice.toFields());
  map.set(key, Bool(true).toField()); 
  beforeAll(async () => {
    appChain = TestingAppChain.fromRuntime({
      modules: { ExtendedSpyMaster: ExtendedSpyMaster, Balances: Balances,},
      config: { ExtendedSpyMaster: {},Balances: {},},
    });

    appChain.setSigner(aliceKey);
    await appChain.start();
    spymaster = appChain.runtime.resolve("ExtendedSpyMaster");
    balances = appChain.runtime.resolve("Balances");
  });

  it("adding an agent", async () => {
    const tx = appChain.transaction(alice, () => {
      spymaster.addAgent( AgentId.from(0), new SecurityCode({ char0: new Field(97), char1: new Field(98) }),);
    });
    await tx.sign();
    await tx.send();
    await appChain.produceBlock();

    const agent = await appChain.query.runtime.ExtendedSpyMaster.agents.get(AgentId.from(0));

    expect(agent?.agentId).toEqual(AgentId.from(0));
    expect(agent?.lastMessage).toEqual(UInt64.from(0));
    expect(agent?.securityCode.char0).toEqual(new Field(97));
    expect(agent?.securityCode.char1).toEqual(new Field(98));
  });

  it("process message & update account state", async () => {
    const messageStr = "123456789xyz";
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

    await PrivateMessage.compile();
    const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get( AgentId.from(0),)) as Agent;
    const privateMessageProof = await PrivateMessage.process(agent, message);
    const tx = appChain.transaction(alice, () => { spymaster.setLastMessage(agent.agentId, privateMessageProof)});

    await tx.sign();
    await tx.send();
    let block = await appChain.produceBlock();

    expect(block).toBeTruthy();
    expect(block?.txs[0]?.status).toBeTruthy();

    const new_agent = await appChain.query.runtime.ExtendedSpyMaster.agents.get(AgentId.from(0));
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
      const agent = await appChain.query.runtime.ExtendedSpyMaster.agentToBlockInfo.get(agentId);
      const blockInfo =await appChain.query.runtime.ExtendedSpyMaster.agentToBlockInfo.get(agentId);

      expect(agent).toBeDefined();
      expect(blockInfo).toBeDefined();

      expect(blockInfo!.blockHeight).toEqual(blockHeight);
      expect(blockInfo!.transactionSender).toEqual(alice);
      expect(blockInfo!.senderNonce).toEqual(UInt64.from(0));
    }
  });

  describe("When Cases fail", () => {
    it("When message is longer than 12 characters long", async () => {
      const messageStr = "123456789xyza"; // 13 characters
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({ messageNumber: UInt64.from(1), agentId: AgentId.from(0), body: asciiFields, securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      });

      await PrivateMessage.compile();
      const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get( AgentId.from(0))) as Agent;
      expect(() =>
        PrivateMessage.process(agent, message),
      ).rejects.toThrowError();
    });

    it("When message is shorter than 12 characters long", async () => {
      const messageStr = "123456789xy"; // 11 characters
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({ messageNumber: UInt64.from(1), agentId: AgentId.from(0), body: asciiFields, securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      });

      // for generating the proof of message validity
      await PrivateMessage.compile();
      const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get( AgentId.from(0))) as Agent;
      expect(() =>
        PrivateMessage.process(agent, message),
      ).rejects.toThrowError();
    });

    it("When the security code does not match - fail", async () => {
      const messageStr = "123456789xyz";
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({ messageNumber: UInt64.from(1), agentId: AgentId.from(0), body: asciiFields, securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(99),
        }),
      });

      await PrivateMessage.compile();
      const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get( AgentId.from(0))) as Agent;
      expect(() => PrivateMessage.process(agent, message)).rejects.toThrowError(
        "Security code does not match",
      );
    });

    it("When the message no. is not greater than the last message no - fail", async () => {
      const messageStr = "123456789xyz";
      const asciiFields = [];
      for (var i = 0; i < messageStr.length; i++) {
        asciiFields.push(Field(messageStr.charCodeAt(i)));
      }
      const message = new Message({messageNumber: UInt64.from(0), agentId: AgentId.from(0), body: asciiFields, securityCode: new SecurityCode({
          char0: new Field(97),
          char1: new Field(98),
        }),
      });

      await PrivateMessage.compile();
      const agent = (await appChain.query.runtime.ExtendedSpyMaster.agents.get(AgentId.from(0), )) as Agent;
      expect(() => PrivateMessage.process(agent, message)).rejects.toThrowError(
        "Message no. is not greater than the agent's last message",
      );
    });
  });
});

