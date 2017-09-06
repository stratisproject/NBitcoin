using System;
using System.Collections.Generic;
using System.Linq;

namespace NBitcoin
{
	public class WithdrawTransaction :IBitcoinSerializable
	{
		public uint256 ParentGenesis;

		public SpvProof SpvProof;


		public void ReadWrite(BitcoinStream stream)
		{
			throw new NotImplementedException();
		}
	}

    public class SpvProof
	{
		public uint256 Genesis;

		public SpvHeaders SpvHeaders;

		public Transaction Lock;

	    public Transaction CoinBase;

		public PartialMerkleTree MerkleProof;

		public static Script CreateScript(SpvProof proof)
		{
			var scriptSignature = new Script(
				Op.GetPushOp(proof.Genesis.ToBytes()),
				Op.GetPushOp(proof.CoinBase.ToBytes()),
				Op.GetPushOp(proof.Lock.ToBytes()),
				Op.GetPushOp(proof.MerkleProof.ToBytes()),
				Op.GetPushOp(proof.SpvHeaders.ToBytes()));

			return scriptSignature;
		}

		public static SpvProof CreateProof(IEnumerable<byte[]> stack)
		{
			var items = stack.ToArray();
			var proof = new SpvProof();
			proof.Genesis = new uint256(items[0]);
			proof.CoinBase = new Transaction(items[1]);
			proof.Lock = new Transaction(items[2]);
			proof.MerkleProof = new PartialMerkleTree(items[3]);
			proof.SpvHeaders = new SpvHeaders(items[4]);
			return proof;
		}
	}

	public class SpvHeaders : IBitcoinSerializable
	{
		public List<BlockHeader> Headers;

		public SpvHeaders()
		{ }

		public SpvHeaders(byte[] bytes)
		{
			this.FromBytes(bytes);
		}

		public void ReadWrite(BitcoinStream stream)
		{
			stream.ReadWrite(ref this.Headers);
		}
	}
}
