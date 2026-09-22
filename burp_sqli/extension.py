# -*- coding: utf-8 -*-
"""Burp Suite extension (Jython): export a selected request to a blindsqli config.

This is the thin UI shim. All parsing/serialization lives in `core`, which has
no Burp dependency and is unit-tested separately. Load this file in Burp:
  Extender -> Extensions -> Add -> Extension type: Python -> select extension.py
(Jython standalone JAR must be configured under Extender -> Options.)
"""

import os
import sys

# make the sibling `core` module importable regardless of how Burp loads us
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core  # noqa: E402

from burp import IBurpExtender, IContextMenuFactory  # noqa: E402
from javax.swing import (  # noqa: E402
    JMenuItem, JPanel, JLabel, JComboBox, JTextField, JButton, JFileChooser,
    JOptionPane,
)
from java.awt import GridLayout  # noqa: E402
from java.util import ArrayList  # noqa: E402


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Export to blindsqli")
        callbacks.registerContextMenuFactory(self)
        self._config_path = os.path.join(os.path.expanduser("~"), "blindsqli_config.json")

    # -- context menu -------------------------------------------------------
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        item = JMenuItem("Export to SQLi Tool")

        def on_click(event, inv=invocation):
            try:
                self._export(inv)
            except Exception as exc:  # surface any failure to the user
                JOptionPane.showMessageDialog(
                    None, "Export failed:\n{0}".format(exc),
                    "blindsqli", JOptionPane.ERROR_MESSAGE)

        item.addActionListener(on_click)
        items = ArrayList()
        items.add(item)
        return items

    # -- export flow --------------------------------------------------------
    def _model_from_message(self, message):
        raw = self._helpers.bytesToString(message.getRequest())
        service = message.getHttpService()
        return core.parse_request(raw, service.getProtocol(), service.getHost(),
                                  service.getPort())

    def _export(self, invocation):
        messages = invocation.getSelectedMessages()
        model = self._model_from_message(messages[0])
        params = core.enumerate_parameters(model)
        if not params:
            JOptionPane.showMessageDialog(
                None, "No query/body/cookie parameters found in this request.",
                "blindsqli", JOptionPane.WARNING_MESSAGE)
            return
        self._show_dialog(model, params)

    def _show_dialog(self, model, params):
        panel = JPanel(GridLayout(0, 1, 4, 4))
        panel.add(JLabel("Request:  {0} {1}".format(model.method, model.url)))
        panel.add(JLabel("Vulnerable parameter:"))
        combo = JComboBox([p.label() for p in params])
        panel.add(combo)
        panel.add(JLabel("blindsqli config file:"))
        path_field = JTextField(self._config_path)
        panel.add(path_field)

        browse = JButton("Browse...")

        def on_browse(event):
            chooser = JFileChooser()
            if chooser.showSaveDialog(panel) == JFileChooser.APPROVE_OPTION:
                path_field.setText(chooser.getSelectedFile().getAbsolutePath())

        browse.addActionListener(on_browse)
        panel.add(browse)

        choice = JOptionPane.showConfirmDialog(
            None, panel, "Export to blindsqli", JOptionPane.OK_CANCEL_OPTION)
        if choice != JOptionPane.OK_OPTION:
            return

        selected = params[combo.getSelectedIndex()]
        path = path_field.getText().strip()
        if not path:
            JOptionPane.showMessageDialog(
                None, "Please choose a config file path.",
                "blindsqli", JOptionPane.WARNING_MESSAGE)
            return

        core.export(path, model, selected)
        self._config_path = path
        JOptionPane.showMessageDialog(
            None,
            "Exported the {0} parameter '{1}' to:\n{2}\n\n"
            "Other settings in the file were preserved.".format(
                selected.location, selected.name, path),
            "blindsqli", JOptionPane.INFORMATION_MESSAGE)
