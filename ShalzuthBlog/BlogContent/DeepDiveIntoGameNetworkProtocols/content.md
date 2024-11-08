# A Roadmap to Security Game Testing: Deep Dive into Game Network Protocols

**ff7ecapi** is an educational repository designed to showcase the process of statically dumping assets and communicating over the network in a sample mobile app. This project is not a beginner tutorial but rather an insight into my thought process and the steps involved in reversing mobile app assets and network protocols.

---

## High-Level Overview

To successfully retrieve assets and communicate over the network in mobile applications, the first step is always to obtain the app's binary code. From there, we can begin sniffing network requests and analyzing the app's code to understand its behavior.

The process can be broken down into several key phases, each requiring its own set of tools and techniques. In my approach, I've split the work into separate projects to better isolate each step of the reverse engineering process.

---

### 1. **Download the APK**

The first step in the process is to get the APK file for the app.

- **Project Used:** ApkDumper  
  I use the `qoo` tool to download the APK. You'll need to fill in some additional details, like tokens, during the download process.
  
- **Quick Inspection:**  
  Upon inspecting the APK, I noticed it's a Unity-based app (indicated by the presence of `libil2cpp.so`).

- **Extract Metadata:**
  I used  `il2cppdumper` to extract the metadata. This step helps in understanding how the Unity app is structured, and it often reveals useful information about the app's code.
  
  - In this case, the `global-metadata.bin` file is encrypted. The encryption is a simple XOR, as we can see in the `libil2cpp.so`. The XOR key can be extracted statically from the `.so` file. The code for dumping the XOR encryption is available here:  
```csharp:https://github.com/shalzuth/ff7ecapi/blob/64d1a6512d60f731f4d9afe43148a719a7a0f067/ApkDumper/Unity.cs#L28-L41
public static byte[] ExtractXor()
{
    var disassembler = CapstoneDisassembler.CreateArm64Disassembler(Gee.External.Capstone.Arm64.Arm64DisassembleMode.Arm);
    var armCode = File.ReadAllBytes("libil2cpp.so");
    var sigscan = new SigScanner(armCode);
    var addr = sigscan.FindPattern("0A 19 40 92 6B 6A 68 38"); // search "Metadata" in the file
    var xorLocs = disassembler.Disassemble(armCode.Skip(addr - 12).Take(12).ToArray());
    var pageAddress = ((addr - 12 + xorLocs[0].Address - 0x1000) & 0xfffff000) - 0x1000;
    var pageOffset = int.Parse(xorLocs[0].Operand.Split("0x")[1], NumberStyles.HexNumber);
    var absOffsetl = int.Parse(xorLocs[2].Operand.Split("#").Last().Replace("0x", ""), NumberStyles.HexNumber);
    var s = (int)pageAddress + pageOffset + absOffsetl;
    var xor = armCode.Skip(s).Take(128).ToArray();
    return xor;
}
```

---

### 2. **Inspect the Network & File Structures**

Once we've extracted the metadata, we need to analyze how the app structures its network communications and file formats. Typically, these are closely related.

- **Tool Used:** dnSpy for inspecting dummy DLLs.

- **Frameworks Identified:**  
  By examining the dummy DLLs from the IL2CPP dump, I identified common data serialization formats like Protobuf and MessagePack. These are widely used in mobile games for efficient data transmission.

#### 2.1 **Dump Protobuf Files**

Protobuf is a commonly used serialization format, and here's how I extracted it:

- I've been using [SteamKit's ProtobufDumper](https://github.com/shalzuth/ff7ecapi/blob/main/PbDumper/Dumper.cs) to dump out Protobuf definitions. The process involves finding the static constructor address in the dummy DLL and using that to locate and dump the raw Protobuf binary.
  
#### 2.2 **Dump MessagePack Files**

For MessagePack, I manually reversed the classes in the dummy DLLs and reconstructed them. Although this method isn't as accurate as dumping Protobuf binaries, it worked well in this case:  
[MessagePack Dumper Code](https://github.com/shalzuth/ff7ecapi/blob/main/MpDumper/Dumper.cs).

#### 2.3 **Dealing with Protection Mechanisms**

Sometimes, the files are protected to prevent easy extraction. For instance, MessagePack files in this app are encrypted. To break this protection, I compared this app with others by the same developer (Applibot), like **Nier Reincarnation**. By comparing Nier with FF7EC, I discovered that the decryption method was almost identical, with only small differences like an altered mask length.

Check out the relevant code here:  
[Nier Reincarnation Comparison](https://github.com/NieR-Rein-Guide/nier-rein-apps/blob/6d1e6f717b5a5ea90e3e5583184d2b2fb8766d19/src/NierReincarnation.Datamine/Command/Data/ExportAssetsCommand.cs)

---

### 3. **Inspect Network Traffic and Replicate Requests**

Next, we need to observe the network traffic to figure out how to interact with the app's server, using the structures we've just uncovered.

- **Tool Used:** Fiddler and Titanium for live traffic inspection.

- **Steps:**
  1. **Proxy Setup:** I set up a proxy to intercept the app's network traffic. This lets me capture requests and study the payloads.
  2. **Observe Headers:** Different stages of authentication and interaction use different headers, so I carefully monitored these throughout the process.  
```csharp:https://github.com/shalzuth/ff7ecapi/blob/64d1a6512d60f731f4d9afe43148a719a7a0f067/Utils/HttpRequest.cs#L90-L115)
requestMessage.Headers.Add("Accept", "application/protobuf");
requestMessage.Headers.Add("Accept-Encoding", "lz4");
requestMessage.Headers.Add("Accept-Language", "en-US,en;q=0.9");
requestMessage.Headers.Add("User-Agent", "FF7EC.96/32 CFNetwork/1410.0.3 Darwin/22.6.0");
requestMessage.Headers.Add("x-country-code", "US");
requestMessage.Headers.Add("x-battle-server-area-id", "1");
requestMessage.Headers.Add("x-content-encoding-secure", "1");
requestMessage.Headers.Add("x-device-name", "iPhone12,1");
requestMessage.Headers.Add("x-advertising-id", "00000000-0000-0000-0000-000000000000");
requestMessage.Headers.Add("x-platform-type", "1");
requestMessage.Headers.Add("x-device-id", DeviceId.ToString().ToUpper());
requestMessage.Headers.Add("x-terminal-id", DeviceId.ToString().ToUpper());
requestMessage.Headers.Add("x-os-version", "iOS 16.6.1");
requestMessage.Headers.Add("X-Unity-Version", "2021.3.16f1");
requestMessage.Headers.Add("x-app-version", "1.3.20");
requestMessage.Headers.Add("x-language", "en");
requestMessage.Headers.Add("x-server-master-version", "1696816297");
requestMessage.Headers.Add("x-accept-encoding-secure", "1");
requestMessage.Headers.Add("x-keychain-user-id", "123456789123456789");
if (ResponseHeaders.ContainsKey("X-Master-Path")) xmasterpath = ResponseHeaders["X-Master-Path"].First();
requestMessage.Headers.Add("x-master-path", xmasterpath);
```
  3. **Handle Compression & Encryption:**  
     Modern apps often use compression and encryption to protect data. After identifying the relevant compression/encryption methods in the dummy DLL, I used tools like IDA and Ghidra to analyze them. Here's the decryption and decompression code:  
     [Decompression Code](https://github.com/shalzuth/ff7ecapi/blob/main/Utils/Compresso.cs)  
     [Decryption Code](https://github.com/shalzuth/ff7ecapi/blob/main/Utils/Crypto.cs)
  4. **Identify API Endpoints:**  
     Instead of manually listing all possible API endpoints, I used a combination of the dummy DLLs and string dumping tools to parse them automatically.  
```csharp:https://github.com/shalzuth/ff7ecapi/blob/64d1a6512d60f731f4d9afe43148a719a7a0f067/PbDumper/Dumper.cs#L121-L150
foreach (var a in apiClasses)
{
    var cctor = a.GetConstructors().First();
    var cctorOffset = int.Parse(cctor.CustomAttributes.First(a => a.AttributeType.Name == "AddressAttribute").Fields.First(f => f.Name == "Offset").Argument.Value.ToString().Substring(2), System.Globalization.NumberStyles.AllowHexSpecifier);
    var func = disassembler.Disassemble(armCode.Skip(cctorOffset).Take(0x1000).ToArray());
    var area = func.SkipWhile(a => a.Mnemonic != "strb").ToArray();
    var b64 = "";
    var reqType = a.Properties.First(p => p.Name == "RequestParameter").PropertyType.Name;
    var respType = ((GenericInstanceType)a.Methods.First(m => m.Name == "RequestAsync").ReturnType).GenericArguments.First().Name;
    for (var i = 0; i < area.Length; i++)
    {
        if (area[i].Mnemonic == "adrp" && area[i + 1].Mnemonic == "adrp" && area[i + 2].Mnemonic == "ldr" && area[i + 1 + 2].Mnemonic == "ldr")
        {
            var pageAddress = ((cctorOffset + area[i].Address - 0x1000) & 0xfffff000) - 0x1000;
            var p2 = disassembler.Disassemble(armCode.Skip(cctorOffset + (int)area[i + 0].Address - 0x1000).Take(0x20).ToArray())[0];
            var p3 = disassembler.Disassemble(armCode.Skip(cctorOffset + (int)area[i + 2].Address - 0x1000).Take(0x20).ToArray())[0];
            //var pageOffset = int.Parse(area[i].Operand.Split("0x")[1], System.Globalization.NumberStyles.HexNumber);
            var pageOffset = int.Parse(p2.Operand.Split("0x")[1], System.Globalization.NumberStyles.HexNumber);
            var absOffsetl = int.Parse(p3.Operand.Split("#").Last().Replace("0x", "").Replace("]", ""), System.Globalization.NumberStyles.HexNumber);
            var s2 = (int)pageAddress + pageOffset + absOffsetl;
            var s = BitConverter.ToInt32(armCode, s2 - 0x1000);
            var url = stringLiterals[s];
            apiSb.AppendLine("        public async Task<" + respType + "> " + reqType.Replace("Request", "") + "(" + reqType + " request)");
            apiSb.AppendLine("        {");
            apiSb.AppendLine("            return await http.ApiRequestAsync<" + respType + ">(apiUrl + \"" + url + "\".Replace(\"{0}\",userId.ToString()), request);");
            apiSb.AppendLine("        }");
            break;
        }
    }
}
```

---

### 4. **Bringing Everything Together**

At this point, we've extracted all the information we need to interact with the app's network and file systems.

- **Downloading Assets Over the Web:**  
  Now that we've reversed the network protocols, we can directly download game assets without needing to re-download the entire APK or wait for app updates. This is useful for continuous content upgrades.  
  [Asset Download Code](https://github.com/shalzuth/ff7ecapi/blob/main/NetDumper/Dumper.cs)

- **Extracting Game Images:**  
  I used `AssetsTools` to dump Unity assets, which helped me extract images and other resources from the app's game files.

- **Account Info Extraction:**  
  I created a script to log into the app, dump account data, and access user-specific assets.  
```csharp:https://github.com/shalzuth/ff7ecapi/blob/64d1a6512d60f731f4d9afe43148a719a7a0f067/ff7ecapi/Program.cs#L43-L45
var login = await api.PostAuthSession(new PostAuthSessionRequest { DeviceUuid = accountInfo.DeviceUuid.ToLower(), LoginToken = accountInfo.LoginToken });
var title = await api.PostPvtUserTitle(new PostPvtUserTitleRequest { });
```

- **Search for Other Players:**  
  I also implemented functionality to search for other players' data from the app.  
```csharp:https://github.com/shalzuth/ff7ecapi/blob/64d1a6512d60f731f4d9afe43148a719a7a0f067/ff7ecapi/Program.cs#L52-L53
var profileResult = await api.PostPvtProfileGet(new PostPvtProfileGetRequest { DisplayUserId = userId });
```

- **Dump Announcements:**  
  Finally, I wrote code to dump game announcements, allowing for a comprehensive data collection from the app.  
```csharp:https://github.com/shalzuth/ff7ecapi/blob/64d1a6512d60f731f4d9afe43148a719a7a0f067/ff7ecapi/Program.cs#L59-L71
var announcements = await api.PostAnnouncementList(new PostAnnouncementListRequest
{
    AnnouncementTypeList = { new List<AnnouncementType> { AnnouncementType.Event, AnnouncementType.Gacha, AnnouncementType.Campaign, AnnouncementType.Sale, AnnouncementType.Info,
        AnnouncementType.Bug, AnnouncementType.Update, AnnouncementType.Maintenance, AnnouncementType.DataUpdate, AnnouncementType.ImportantInfo, AnnouncementType.Topic} },
    Limit = 2,
    Offset = 0
});
foreach (var announcement in announcements.AnnouncementSummaryList)
{
    var detailedInfo = await api.PostAnnouncementDetail(new PostAnnouncementDetailRequest { Id = announcement.AnnouncementId });
    Console.WriteLine(announcement);
    Console.WriteLine(detailedInfo);
}
```

---

### 5. **The Gray Area**

It's important to note that some aspects of in-game automation, particularly those that could negatively impact the game's economy or integrity, have been intentionally excluded from this project. These actions often involve additional encrypted steps and different network protocols, and are typically discouraged or prohibited by most games.

---

## Conclusion

This project provides an in-depth look into the process of reverse engineering mobile apps to dump assets and communicate with servers. While this is not a beginner's guide, it should offer valuable insights for those interested in mobile app reverse engineering, especially when working with complex formats like Protobuf and MessagePack.

Feel free to explore the source code and contribute to the repository if you have suggestions or improvements!

## Source
(GitHub)[https://github.com/shalzuth/ff7ecapi]
