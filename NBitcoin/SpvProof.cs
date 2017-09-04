using System;
using System.Collections.Generic;

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
	    public List<BlockHeader> SpvHeaders;

	    public uint256 Genesis;

	    public Transaction Lock;

	    public Transaction CoinBase;

	    public Transaction CoinStake;

		public PartialMerkleTree MerkleProof;
    }
}
