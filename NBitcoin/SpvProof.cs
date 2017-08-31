using System;
using System.Collections.Generic;
using System.Text;

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
	    private List<BlockHeader> Headers;

    }
}
