using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Threading;
using System.Security.Cryptography;
using System.Reflection.Emit;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace BestIdentityBackend
{
    internal class Program
    {
        static Dictionary<string, UsersData> users_data = new Dictionary<string, UsersData>();
        static string current = System.IO.Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
        static void Main(string[] args)
        {
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add("http://*/");
            listener.Start();

            Console.WriteLine($"Identity Server started: {listener.Prefixes.First()}");

            for (; ; )
            {
                HttpListenerContext context = listener.GetContext();

                ThreadPool.QueueUserWorkItem((state) =>
                {
                    var request = ((HttpListenerContext)state).Request;
                    var response = ((HttpListenerContext)state).Response;
                    string raw_url = Uri.UnescapeDataString(request.RawUrl);
                    string identity = GetBytesHash(Encoding.UTF8.GetBytes($"{request.UserAgent}~{request.UserHostAddress}~{request.UserHostName}~{request.UserLanguages}"));
                    string os_name = GetOperatingSystem(request.UserAgent);
                    string browsser_name = GetBrowserName(request.UserAgent);

                    Console.WriteLine($"{identity} {raw_url}");

                    if (!users_data.ContainsKey(identity))
                    {
                        users_data.Add(identity, new UsersData(request.UserHostAddress.ToString(), request.UserLanguages.First(), browsser_name, Permision.USER, os_name));
                        users_data[identity].debug.Add($"[NEW IDENTITY] ({users_data[identity].last_request}) {identity} {Permision.GetString(users_data[identity].permision)}");
                        response.Redirect(raw_url);
                        response.Close();
                        return;
                    }

                    if (raw_url == "/debug")
                    {
                        UsersData data = users_data[identity];
                        data.last_time = DateTime.Now;
                        users_data[identity].debug.Add($"[SHOW DEBUG] ({data.last_request}) {identity} {Permision.GetString(data.permision)}");

                        string html = File.ReadAllText(Path.Combine(current, "public", "show_users.html"));

                        List<KeyValuePair<string, UsersData>> ShortedData = users_data.OrderByDescending(user => user.Value.last_time).ToList();

                        string sb = "";
                        foreach (var u in ShortedData)
                        {
                            string mid = "";
                            foreach (var v in u.Value.debug)
                            {
                                mid += $"<p>{v}</p>";
                                //Console.WriteLine(mid);
                            }
                            //Console.WriteLine(mid);
                            sb += $@"<details>
                    <summary>Identity: {u.Key} System: {u.Value.system_name} {u.Value.browser_name} IP: {u.Value.public_ip} {FormatTimeSpan(u.Value.last_request)}</summary>
                    <div class=""folder""
                        {mid}
                    </div>
                </details>";
                        }

                        html = html.Replace("<!--users-->", sb);
                        byte[] buffer = Encoding.UTF8.GetBytes(html);
                        response.OutputStream.Write(buffer, 0, buffer.Length);
                        response.Close();
                        return;
                    }

                    {
                        UsersData data = users_data[identity];
                        data.last_time = DateTime.Now;
                        data.debug.Add($"[NEXT REQUEST] ({data.last_time}) {identity} {raw_url} {request.HttpMethod}");

                        string html = $"{raw_url}, {identity}";
                        byte[] buffer = Encoding.UTF8.GetBytes(html);
                        response.OutputStream.Write(buffer, 0, buffer.Length);
                        response.Close();
                    }

                }, context);
            }
        }
        static string FormatTimeSpan(TimeSpan timeSpan)
        {
            string result = "";

            if (timeSpan.Days > 0)
            {
                result += $"{timeSpan.Days} d ";
            }

            if (timeSpan.Hours > 0)
            {
                result += $"{timeSpan.Hours} h ";
            }

            if (timeSpan.Minutes > 0)
            {
                result += $"{timeSpan.Minutes} min ";
            }

            if (timeSpan.Seconds >= 0)
            {
                result += $"{timeSpan.Seconds} s ";
            }

            // Trim any trailing space
            return result.Trim();
        }
        public static string GetBytesHash(byte[] input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToUpper();
            }
        }
        static string GetOperatingSystem(string userAgent)
        {
            // Use regular expressions to extract operating system information from User-Agent string
            Regex osRegex = new Regex(@"\((.*?)\)");
            Match osMatch = osRegex.Match(userAgent);

            if (osMatch.Success)
            {
                // The first group captures the content inside the parentheses, which often includes OS information
                string osInfo = osMatch.Groups[1].Value;

                // You may want to further parse or clean up the extracted information based on your needs
                return osInfo;
            }

            // Return a default value or handle the case where OS information is not found
            return "Unknown";
        }
        static string GetBrowserName(string userAgent)
        {
            // Use regular expressions to extract browser information from User-Agent string
            Regex browserRegex = new Regex(@"(?:MSIE|Trident.*?rv:|Edge/|Chrome/|Firefox/|Safari/)(.*?)(?:\s|$)");
            Match browserMatch = browserRegex.Match(userAgent);

            if (browserMatch.Success)
            {
                // The first group captures the content inside the parentheses, which often includes browser information
                string browserInfo = browserMatch.Groups[1].Value;

                // You may want to further parse or clean up the extracted information based on your needs
                return browserInfo;
            }

            // Return a default value or handle the case where browser information is not found
            return "Unknown";
        }
    }
    public class UsersData
    {
        public IPAddress public_ip { get; set; }
        public string language { get; set; }
        public string browser_name { get; set; }
        public DateTime last_time { get; set; }
        public string system_name { get; set; }
        public TimeSpan last_request { get { return DateTime.Now - last_time; } }
        public int permision = 0;
        public List<string> debug { get; set; }
        public List<object> items { get; set; }

        public UsersData(string public_ip, string language, string browser_name, int permision = 3, string system_name = "Unknown")
        {
            debug = new List<string>();
            items = new List<object>();
            this.system_name = system_name;
            this.public_ip = IPAddress.TryParse(public_ip, out IPAddress adress) ? adress : null;
            this.language = language;
            this.browser_name = browser_name;
        }
    }
    struct Permision
    {
        public static int USER { get { return 0; } }
        public static int ADMIN { get { return 1; } }
        public static int OWNER { get { return 2; } }
        public static int GetUserBy(string name)
        {
            string a = name.ToLower();
            return a == "user" ? USER : a == "admin" ? ADMIN : a == "owner" ? OWNER : 0;
        }
        public static string GetString(int permision)
        {
            return permision == 0 ? "USER" : permision == 1 ? "ADMIN" : permision == 2 ? "OWNER" : string.Empty;
        }
    }
}
