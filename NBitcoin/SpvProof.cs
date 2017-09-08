using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NBitcoin
{
	public class SpvProof
	{
		public uint256 Genesis;

		public SpvHeaders SpvHeaders;

		public Transaction Lock;

		public int OutputIndex;

	    public Transaction CoinBase;

		public PartialMerkleTree MerkleProof;

		public Script DestinationScript;

		public static Script CreateScript(SpvProof proof)
		{
			var scriptSignature = new Script(
				Op.GetPushOp(proof.Genesis.ToBytes()),
				Op.GetPushOp(proof.CoinBase.ToBytes()),
				Op.GetPushOp(WriteIndex(proof.OutputIndex)),
				Op.GetPushOp(proof.Lock.ToBytes()),
				Op.GetPushOp(proof.MerkleProof.ToBytes()),
				Op.GetPushOp(proof.SpvHeaders.ToBytes()),
				Op.GetPushOp(proof.DestinationScript.ToBytes()));

			return scriptSignature;
		}

		public static SpvProof CreateProof(IEnumerable<byte[]> stack)
		{
			var items = stack.ToArray();
			var proof = new SpvProof();
			proof.Genesis = new uint256(items[0]);
			proof.CoinBase = new Transaction(items[1]);
			proof.OutputIndex = ReadIndex(items[2]);
			proof.Lock = new Transaction(items[3]);
			proof.MerkleProof = new PartialMerkleTree(items[4]);
			proof.SpvHeaders = new SpvHeaders(items[5]);
			proof.DestinationScript = new Script(items[6]);
			return proof;
		}

		public static int ReadIndex(byte[] array)
		{
			using (var mem = new MemoryStream(array))
			{
				int ret = 0;
				var stream = new BitcoinStream(mem, false);
				stream.ReadWrite(ref ret);
				return ret;
			}
		}

		public static byte[] WriteIndex(int number)
		{
			using (var mem = new MemoryStream())
			{
				var stream = new BitcoinStream(mem, true);
				stream.ReadWrite(ref number);
				return mem.ToArray();
			}
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
