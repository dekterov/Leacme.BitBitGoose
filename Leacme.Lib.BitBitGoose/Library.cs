// Copyright (c) 2017 Leacme (http://leac.me). View LICENSE.md for more information.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using LiteDB;
using NBitcoin;
using NBitcoin.DataEncoders;
using QBitNinja.Client;
using QBitNinja.Client.Models;

namespace Leacme.Lib.BitBitGoose {

	public class Library {

		private LiteDatabase db = new LiteDatabase(typeof(Library).Namespace + ".Settings.db");
		public LiteCollection<BsonDocument> BitCollection { get; }

		public Library() {
			BitCollection = db.GetCollection(nameof(BitCollection));
		}

		/// <summary>
		/// Generate new BitcoinSecret programmatically or from an imported hexadecimal private key.
		/// /// </summary>
		/// <param name="privateKeyHexString">Optional private key to use for BitcoinSecret generation.</param>
		/// <param name="network">Bitcoin Network (main, test, etc.)</param>
		/// <returns>BitcoinSecret based on the Bitcoin network selected.</returns>
		public BitcoinSecret GetOrCreateSecretFromPrivateKey(string privateKeyHexString = null, NetworkType network = NetworkType.Mainnet) {
			if (privateKeyHexString != null) {
				if (privateKeyHexString.Length != 64 && !Regex.IsMatch(privateKeyHexString, @"\A\b[0-9a-fA-F]+\b\Z")) {
					throw new ArgumentException("Invalid private key. Needs to be a hexadecimal string of length 64.");
				}
				return new BitcoinSecret(new Key(Enumerable.Range(0, privateKeyHexString.Length / 2).Select(z => Convert.ToByte(privateKeyHexString.Substring(z * 2, 2), 16)).ToArray(), count: 32), Network.GetNetwork(network.ToString().ToLower()));
			} else {
				return new BitcoinSecret(new Key(), Network.GetNetwork(network.ToString().ToLower()));
			}
		}

		/// <summary>
		/// Extract a network-independent hexadecimal private key of lengh 64 from a BitcoinSecret.
		/// /// </summary>
		/// <param name="secret"></param>
		/// <returns></returns>
		public string GetPrivateKeyFromSecret(BitcoinSecret secret) {
			return BitConverter.ToString(secret.ToBytes()).Replace("-", string.Empty).Substring(0, 64).ToLower();
		}

		/// <summary>
		/// Encrypt and store the hexadecimal private key in the database. Only one key is allowed per database.
		/// /// </summary>
		/// <param name="hexEncodedPrivateKey"></param>
		/// <param name="password">Password with which to encrypt the key before storing.</param>
		/// <param name="network">Bitcoin network of the key.</param>
		/// <param name="replaceIfExists">Replaces stored key with a new one. Warning when using this since the deletion is irreversable.</param>
		public void StoreEncryptedPrivateKey(string hexEncodedPrivateKey, string password, NetworkType network = NetworkType.Mainnet, bool replaceIfExists = false) {
			var secret = GetOrCreateSecretFromPrivateKey(hexEncodedPrivateKey, network);
			var retrKeyDoc = BitCollection.FindOne(z => z.ContainsKey("BPK1"));
			if (retrKeyDoc != null) {
				if (replaceIfExists) {
					BitCollection.Delete(z => z.ContainsKey("BPK1"));
					InsertBPK1();
				}
			} else {
				InsertBPK1();
			}
			void InsertBPK1() {
				BitCollection.Insert(new BsonDocument {
					["BPK1"] = secret.Encrypt(password).ToString(), ["BPK1NW"] = network.ToString().ToLower()
				});
			}
		}

		/// <summary>
		/// Decrypt and retrieve the BitcoinSecret stored in the database.
		/// /// </summary>
		/// <param name="password">The password with which to decrypt the key.</param>
		/// <returns>The stored BitcoinSecret if exists or null if does not. Throws SecurityException on invalid password.</returns>
		public BitcoinSecret RetrieveDecryptedPrivateKey(string password) {
			var retrKeyDoc = BitCollection.FindOne(z => z.ContainsKey("BPK1"));
			if (retrKeyDoc != null) {
				return BitcoinEncryptedSecret.Create(retrKeyDoc["BPK1"], Network.GetNetwork(retrKeyDoc["BPK1NW"])).GetSecret(password);
			} else return null;
		}

		/// <summary>
		/// Get the QBitNinja client to be able to read the transaction and balance from the Bitcoin network via its API.
		/// /// </summary>
		/// <param name="network">The Bitcoin network (main, test, etc.)</param>
		/// <returns>The QBitNinja Bitcoin network client.</returns>
		public QBitNinjaClient ConnectToBitcoinNetwork(NetworkType network = NetworkType.Mainnet) {
			return new QBitNinjaClient(Network.GetNetwork(network.ToString().ToLower()));
		}

		/// <summary>
		/// Get the list of transactions for a particular address on the Bitcoin network.
		/// /// </summary>
		/// <param name="client">The QBitNinja Bitcoin network client.</param>
		/// <param name="secret">The BitcoinSecret for which to retrieve the transactions.</param>
		/// <returns>Details of transactions.</returns>
		public async Task<List<BalanceOperation>> GetTransactions(QBitNinjaClient client, BitcoinSecret secret) {
			var balance = await client.GetBalance(secret.PubKeyHash.GetAddress(secret.Network));
			if (balance.Operations.Count > 0) {
				return balance.Operations;
			} else {
				return new List<BalanceOperation>();
			}
		}

		/// <summary>
		/// Get the balance in BTC for a particular address on the Bitcoin network.
		/// /// </summary>
		/// <param name="client">The QBitNinja Bitcoin network client.</param>
		/// <param name="secret">The BitcoinSecret for which to retrieve the balance.</param>
		/// <returns>The balance in BTC.</returns>
		public async Task<decimal> GetBalanceInBTC(QBitNinjaClient client, BitcoinSecret secret) {
			var balanceSum = await client.GetBalanceSummary(secret.PubKeyHash.GetAddress(secret.Network));
			if (balanceSum.Confirmed.TransactionCount > 0) {
				return balanceSum.Confirmed.Amount.ToDecimal(MoneyUnit.BTC);
			} else {
				return 0;
			}
		}

		/// <summary>
		/// Get the public Bitcoin address which can be shared with others to receive Bitcoins.
		/// /// </summary>
		/// <param name="secret">The BitcoinSecret for which to get the public address.</param>
		/// <returns>The public Bitcoin address.</returns>
		public string GetPublicBitcoinAddress(BitcoinSecret secret) {
			return secret.PubKeyHash.GetAddress(secret.Network).ToString();
		}

		/// <summary>
		/// Convert Base58 Wallet Import Format string to a hexadecimal string length 64.
		/// /// </summary>
		/// <param name="base58EncodedPrivateKey">The Base58 encoded string to convert.</param>
		/// <returns>The hexadecimal string.</returns>
		public string GetHexStringFromBase58EncodedPK(string base58EncodedPrivateKey) {
			return BitConverter.ToString(Encoders.Base58.DecodeData(base58EncodedPrivateKey)).Replace("-", string.Empty).Substring(0, 64).ToLower();
		}

	}
}