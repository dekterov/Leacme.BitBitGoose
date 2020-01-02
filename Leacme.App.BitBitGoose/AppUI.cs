// Copyright (c) 2017 Leacme (http://leac.me). View LICENSE.md for more information.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Leacme.Lib.BitBitGoose;
using NBitcoin.DataEncoders;

namespace Leacme.App.BitBitGoose {

	public class AppUI {

		private StackPanel rootPan = (StackPanel)Application.Current.MainWindow.Content;
		private Library lib = new Library();

		public AppUI() {
			var blurb1 = App.TextBlock;
			blurb1.TextAlignment = TextAlignment.Center;
			blurb1.Text = "Create or Import a your private Bitcoin key to view its public address and balance.";

			var nwBt = App.Button;
			nwBt.Content = "Create New";

			var ipr = App.HorizontalFieldWithButton;
			ipr.holder.HorizontalAlignment = HorizontalAlignment.Center;
			ipr.holder.Children.Insert(0, nwBt);
			ipr.label.Text = "or import WIF or Hex Private Key:";
			ipr.field.Width = 300;
			ipr.button.Content = "Import Key";

			var dbBlurb = App.TextBlock;
			dbBlurb.TextAlignment = TextAlignment.Center;
			dbBlurb.Text = "No private Bitcoin key stored in database";
			var dbRetrKey = App.TextBox;
			dbRetrKey.Width = 0;
			dbRetrKey.IsReadOnly = true;
			var dbBt = App.Button;
			dbBt.IsEnabled = false;
			dbBt.Content = "View Private Key";
			var dbHolder = App.HorizontalStackPanel;
			dbHolder.HorizontalAlignment = HorizontalAlignment.Center;
			dbHolder.Children.AddRange(new List<IControl>() { dbBlurb, dbRetrKey, dbBt });

			var balBlurb = App.TextBlock;
			balBlurb.Text = "Balance:";
			var balField = App.TextBox;
			balField.Width = 140;
			balField.IsReadOnly = true;

			var pubBlurb = App.TextBlock;
			pubBlurb.Text = "Your public Bitcoin address:";
			var pubField = App.TextBox;
			pubField.Width = 400;
			pubField.IsReadOnly = true;

			var pubHolder = App.HorizontalStackPanel;
			pubHolder.HorizontalAlignment = HorizontalAlignment.Center;
			pubHolder.Children.AddRange(new List<IControl>() { pubBlurb, pubField, balBlurb, balField });

			var txPan = App.DataGrid;
			txPan.Height = 330;

			rootPan.Children.AddRange(new List<IControl>() { blurb1, ipr.holder, dbHolder, pubHolder, txPan });

			nwBt.Click += async (z, zz) => {
				await InitiateConfirmationLoadingAsync(null);
			};

			ipr.button.Click += async (z, zz) => {
				var importCandt = ipr.field.Text?.Trim();
				if (!string.IsNullOrWhiteSpace(importCandt)) {
					var keyToStore = "";
					if (importCandt.Length == 64 && Regex.IsMatch(importCandt, @"\A\b[0-9a-fA-F]+\b\Z")) {
						keyToStore = importCandt;
					} else {
						try {
							Encoders.Base58Check.DecodeData(importCandt);
							keyToStore = lib.GetHexStringFromBase58EncodedPK(importCandt);
						} catch (Exception) {
							ipr.field.Text = "";
							ipr.field.Watermark = "Invalid key - requires base58 or hex string.";
						}
					}
					if (!string.IsNullOrWhiteSpace(keyToStore)) {
						ipr.field.Text = ipr.field.Watermark = "";
						await InitiateConfirmationLoadingAsync(keyToStore);
					}
				}
			};

			async Task InitiateConfirmationLoadingAsync(string key) {
				var pass = await ShowPwdWn(true);
				if (!string.IsNullOrEmpty(pass)) {
					var newKey = !string.IsNullOrWhiteSpace(key) ? key : lib.GetPrivateKeyFromSecret(lib.GetOrCreateSecretFromPrivateKey());
					lib.StoreEncryptedPrivateKey(newKey, pass);
					LoadKeyFromDb(pass);
				}
			}

			LoadKeyFromDb(null);
			async void LoadKeyFromDb(string pass) {
				if (lib.BitCollection.FindOne(z => z.ContainsKey("BPK1")) != null) {
					nwBt.IsEnabled = false;
					ipr.field.IsEnabled = false;
					ipr.button.IsEnabled = false;
					dbBlurb.Text = "Loading key from database...";
					if (pass == null) {
						pass = await ShowPwdWn(false);
					}
					if (string.IsNullOrEmpty(pass)) {
						LoadKeyFromDb(null);
					} else {
						try {
							var rertSecret = lib.RetrieveDecryptedPrivateKey(pass);
							dbBlurb.Text = "Loaded your private Bitcoin key from database: ";
							dbBt.IsEnabled = true;
							dbBt.Click += async (z, zz) => {
								var confPass = await ShowPwdWn(false);
								if (confPass.Equals(pass)) {
									dbRetrKey.Width = 340;
									dbRetrKey.Text = lib.GetPrivateKeyFromSecret(rertSecret);
									dbBt.IsEnabled = false;
								}
							};
							pubField.Text = lib.GetPublicBitcoinAddress(rertSecret);
							balField.Text = (await lib.GetBalanceInBTC(lib.ConnectToBitcoinNetwork(), rertSecret)).ToString() + " BTC";
							txPan.Items = await lib.GetTransactions(lib.ConnectToBitcoinNetwork(), rertSecret);
						} catch (SecurityException) {
							LoadKeyFromDb(null);
						}
					}
				}
			}
		}

		private async Task<string> ShowPwdWn(bool doEncrypt) {
			var pwdWn = App.NotificationWindow;
			pwdWn.Title = "Security Dialog";
			pwdWn.Height = 240;
			var pwdPan = (StackPanel)pwdWn.Content;

			string retPass = "";
			var prompt1 = App.TextBlock;
			if (doEncrypt) {
				prompt1.Text = "Encrypt your private key with a password to store in database.";
			} else {
				prompt1.Text = "Decrypt your stored private key from database with your password.";
			}
			prompt1.TextAlignment = TextAlignment.Center;

			var passBlurb1 = App.TextBlock;
			passBlurb1.Text = "Enter password";
			passBlurb1.TextAlignment = TextAlignment.Center;

			var passField1 = App.TextBox;
			passField1.PasswordChar = '*';
			passField1.Width = 150;

			var passBlurb2 = App.TextBlock;
			passBlurb2.Text = "Confirm password";
			passBlurb2.TextAlignment = TextAlignment.Center;

			var passField2 = App.TextBox;
			passField2.PasswordChar = '*';
			passField2.Width = 150;

			var okBt = App.Button;
			okBt.Content = "OK";
			okBt.Click += async (z, zz) => {
				if (string.IsNullOrWhiteSpace(passField1.Text) || string.IsNullOrWhiteSpace(passField2.Text) || !passField1[TextBox.TextProperty].ToString().Equals(passField2[TextBox.TextProperty].ToString())) {
					var badPassWn = App.NotificationWindow;
					badPassWn.Height = 100;
					badPassWn.Width = 200;
					var badPassBlurb1 = App.TextBlock;
					badPassBlurb1.Text = "Passwords invalid or do not match.";
					var badPassBt = App.Button;
					badPassBt.Content = "OK";
					badPassBt.Click += (zzz, zzzzz) => { badPassWn.Close(); };
					((StackPanel)badPassWn.Content).Children.AddRange(new List<IControl> { badPassBlurb1, badPassBt });
					await badPassWn.ShowDialog<Window>(Application.Current.MainWindow);
					return;
				}
				retPass = passField1[TextBox.TextProperty].ToString(); pwdWn.Close();
			};

			var cnlBt = App.Button;
			cnlBt.Content = "Cancel";
			cnlBt.Click += (z, zz) => { pwdWn.Close(); };
			pwdPan.Children.AddRange(new List<IControl> { prompt1, new Control() { Height = 10 }, passBlurb1, passField1, passBlurb2, passField2, new Control() { Height = 10 }, okBt, cnlBt });
			if (!Application.Current.Windows.Any(z => z.Title.Equals(pwdWn.Title))) {
				await pwdWn.ShowDialog<Window>(Application.Current.MainWindow);
			}
			return retPass;
		}
	}
}