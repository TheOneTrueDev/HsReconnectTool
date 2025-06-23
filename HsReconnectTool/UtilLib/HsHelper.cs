using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UtilLib
{
    public class HsHelper
    {
        static readonly HsHelper singletonInst = new HsHelper();
        static readonly int DisconnectTimeoutMs = 5000;

        Firewall firewall;
        bool isForceDisconnected = false;

        public static HsHelper Instance
        {
            get { return singletonInst; }
        }

        static Process[] ListHsProcesses()
        {
            return Process.GetProcessesByName(Constants.HsProcessName);
        }

        static List<iphlpapi.MIB_TCPROW_OWNER_PID> ListHsConnections(Process[] processes)
        {
            var pids = new HashSet<uint>();
            foreach (var p in processes)
                pids.Add((uint)p.Id);

            List<iphlpapi.MIB_TCPROW_OWNER_PID> connections = iphlpapi.GetAllTCPConnections();
            connections = connections.Where(c => pids.Contains(c.ProcessId)).ToList();
            return connections;
        }

        public HsState UpdateHsState()
        {
            Process[] processes = ListHsProcesses();
            List<iphlpapi.MIB_TCPROW_OWNER_PID> connections = ListHsConnections(processes);
            var state = new HsState(processes, connections);

            if (state.IsRunning && firewall == null)
            {
                firewall = Firewall.TryCreate(state.BinaryPath);
            }

            return state;
        }

        public bool IsConnectedToServer
        {
            get
            {
                if (isForceDisconnected)
                    return false;
                return UpdateHsState().IsConnectedToServer;
            }
        }

        void DisconnectViaFirewall()
        {
            if (firewall == null)
            {
                firewall = Firewall.TryCreate(UpdateHsState().BinaryPath);
                if (firewall == null)
                {
                    MessageBox.Show("Failed to create firewall rule. Cannot disconnect safely.", "Reconnect Plugin", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }

            isForceDisconnected = true;
            firewall.EnableRule();
            System.Threading.Thread.Sleep(DisconnectTimeoutMs);
            firewall.DisableRule();
            isForceDisconnected = false;
        }

        public void CloseConnectionsToServer()
        {
            Console.WriteLine("Closing connections using firewall...");
            Task.Factory.StartNew(DisconnectViaFirewall);
        }
    }
}
