﻿namespace HsReconnectTool
{
    partial class FloatReconnectButton
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(FloatReconnectButton));
            this.close_connection_label = new System.Windows.Forms.Label();
            this.disconnected_label = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // close_connection_label
            // 
            this.close_connection_label.BackColor = System.Drawing.Color.Transparent;
            this.close_connection_label.Dock = System.Windows.Forms.DockStyle.Fill;
            this.close_connection_label.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.close_connection_label.Image = ((System.Drawing.Image)(resources.GetObject("close_connection_label.Image")));
            this.close_connection_label.Location = new System.Drawing.Point(0, 0);
            this.close_connection_label.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.close_connection_label.Name = "close_connection_label";
            this.close_connection_label.Size = new System.Drawing.Size(205, 35);
            this.close_connection_label.TabIndex = 0;
            this.close_connection_label.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // disconnected_label
            // 
            this.disconnected_label.BackColor = System.Drawing.Color.Transparent;
            this.disconnected_label.Dock = System.Windows.Forms.DockStyle.Fill;
            this.disconnected_label.Enabled = false;
            this.disconnected_label.Font = new System.Drawing.Font("Belwe Bd BT", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.disconnected_label.Image = ((System.Drawing.Image)(resources.GetObject("disconnected_label.Image")));
            this.disconnected_label.Location = new System.Drawing.Point(0, 0);
            this.disconnected_label.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.disconnected_label.Name = "disconnected_label";
            this.disconnected_label.Size = new System.Drawing.Size(205, 35);
            this.disconnected_label.TabIndex = 1;
            this.disconnected_label.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            this.disconnected_label.Visible = false;
            // 
            // FloatReconnectButton
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.disconnected_label.BackColor = System.Drawing.Color.Transparent;
            this.ClientSize = new System.Drawing.Size(205, 35);
            this.ControlBox = false;
            this.Controls.Add(this.disconnected_label);
            this.Controls.Add(this.close_connection_label);
            this.Margin = new System.Windows.Forms.Padding(2);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "FloatReconnectButton";
            this.Opacity = 0.9D;
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.Text = "FloatReconnectButton";
            this.TopMost = true;
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Label close_connection_label;
        private System.Windows.Forms.Label disconnected_label;
    }
}