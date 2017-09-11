using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NBitcoin
{
	/// <summary>
	/// An SpvProof (Simplified Payment Verification) that is used to proof an output is locked (undependable).
	/// </summary>
	public class SpvProof
	{
		/// <summary>
		/// The genesis hash of the chain where the withdraw lock was created.
		/// </summary>
		public uint256 Genesis;

		/// <summary>
		/// A list of headers on the chain that confirmed the withdraw.
		/// </summary>
		/// <remarks>
		/// The first header represents the block that contains the withdraw lock.
		/// The rest of the headers represent work (how many blocks the withdraw is berried under).
		/// The headers are expected to be a chained of block headers.
		/// </remarks>
		public SpvHeaders SpvHeaders;

		/// <summary>
		/// A transaction that locked some coins to a special op code <see cref="OpcodeType.OP_WITHDRAWPROOFVERIFY"/>.
		/// </summary>
		public Transaction Lock;

		/// <summary>
		/// The index of the output in the that lock transaction that is being refereed to by this SPV Proof.
		/// </summary>
		public int OutputIndex;

		/// <summary>
		/// The coinbase of the block that confirmed the locked transaction.
		/// </summary>
		/// <remarks>
		/// The coinbase can be used to know the block height of the locked transaction.
		/// </remarks>
	    public Transaction CoinBase;

		/// <summary>
		/// A proof that verifies the locking transaction was included in a block.
		/// </summary>
		public PartialMerkleTree MerkleProof;

		/// <summary>
		/// The recipient of the locking transaction.
		/// </summary>
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

		private static int ReadIndex(byte[] array)
		{
			using (var mem = new MemoryStream(array))
			{
				int ret = 0;
				var stream = new BitcoinStream(mem, false);
				stream.ReadWrite(ref ret);
				return ret;
			}
		}

		private static byte[] WriteIndex(int number)
		{
			using (var mem = new MemoryStream())
			{
				var stream = new BitcoinStream(mem, true);
				stream.ReadWrite(ref number);
				return mem.ToArray();
			}
		}
	}

	/// <summary>
	/// A class to serialize a list of block headers.
	/// </summary>
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
