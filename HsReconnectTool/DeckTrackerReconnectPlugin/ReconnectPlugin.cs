﻿using System;
using System.Windows;
using System.Windows.Controls;
using HsReconnectTool;

namespace DeckTrackerReconnectPlugin
{
    public class ReconnectPlugin : Hearthstone_Deck_Tracker.Plugins.IPlugin
    {
        PluginImpl plugin;

        public string Name => "RecunnectPlugin";

        public string Description => "This plugin allows you to disconnect during the game.";

        public string ButtonText => "None";

        public string Author => "Made by: Vaiz - Patched by: TheOneTrueDev";

        public Version Version => Version.Parse("2.0.0");

        public MenuItem MenuItem => plugin != null ? plugin.Menu : null;

        public void OnButtonPress() { }

        public void OnLoad()
        {
            if (plugin != null)
                plugin.Dispose();
            plugin = new PluginImpl();
        }

        public void OnUnload()
        {
            if (plugin != null)
                plugin.Dispose();
            plugin = null;
        }

        public void OnUpdate()
        {
        }
    }
}
