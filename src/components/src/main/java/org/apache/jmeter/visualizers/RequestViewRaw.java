/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.jmeter.visualizers;

import java.awt.BorderLayout;
import java.awt.CardLayout;

import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Document;

import org.apache.jmeter.gui.util.JSyntaxSearchToolBar;
import org.apache.jmeter.gui.util.JSyntaxTextArea;
import org.apache.jmeter.gui.util.JTextScrollPane;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.util.JMeterUtils;
import org.apache.jmeter.visualizers.SearchTextExtension.JEditorPaneSearchProvider;
import org.apache.jorphan.gui.GuiUtils;
import org.apache.jorphan.gui.ui.KerningOptimizer;
import org.apache.jorphan.util.StringUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.auto.service.AutoService;

/**
 * (historical) Panel to view request data
 *
 */
@AutoService(RequestView.class)
public class RequestViewRaw implements RequestView {

    private static final Logger LOGGER = LoggerFactory.getLogger(RequestViewRaw.class);

    // Used by Request Panel
    static final String KEY_LABEL = "view_results_table_request_tab_raw"; //$NON-NLS-1$

    /**
     * If the request data is longer than this limit, a plain {@link JEditorPane} is used
     * instead of the syntax highlighting text area. A negative value disables the fallback.
     */
    private static final int SIMPLE_VIEW_LIMIT =
            JMeterUtils.getPropDefault("view.results.tree.request.simple_view_limit", 10_000); // $NON-NLS-1$

    private static final String CARD_SYNTAX = "syntax"; //$NON-NLS-1$
    private static final String CARD_PLAIN = "plain"; //$NON-NLS-1$

    private JSyntaxTextArea headerData;
    private JSyntaxTextArea sampleDataField;
    /** Fallback view for large request data */
    private JEditorPane sampleDataEditor;
    private CardLayout sampleDataLayout;
    private JPanel sampleDataPanel;

    private JPanel paneRaw; /** request pane content */

    @Override
    public void init() {
        paneRaw = new JPanel(new BorderLayout(0, 5));

        sampleDataField = JSyntaxTextArea.getInstance(20, 80, true);
        sampleDataField.setEditable(false);
        sampleDataField.setLineWrap(true);
        sampleDataField.setWrapStyleWord(true);
        JPanel requestAndSearchPanel = new JPanel(new BorderLayout());
        requestAndSearchPanel.add(new JSyntaxSearchToolBar(sampleDataField).getToolBar(), BorderLayout.NORTH);
        requestAndSearchPanel.add(JTextScrollPane.getInstance(sampleDataField), BorderLayout.CENTER);

        sampleDataEditor = new JEditorPane();
        sampleDataEditor.setEditable(false);
        JPanel requestPlainPanel = new JPanel(new BorderLayout());
        requestPlainPanel.add(
                new SearchTextExtension(new JEditorPaneSearchProvider(sampleDataEditor)).getSearchToolBar(),
                BorderLayout.NORTH);
        requestPlainPanel.add(GuiUtils.makeScrollPane(sampleDataEditor), BorderLayout.CENTER);

        sampleDataLayout = new CardLayout();
        sampleDataPanel = new JPanel(sampleDataLayout);
        sampleDataPanel.add(requestAndSearchPanel, CARD_SYNTAX);
        sampleDataPanel.add(requestPlainPanel, CARD_PLAIN);

        headerData = JSyntaxTextArea.getInstance(20, 80, true);
        headerData.setEditable(false);
        headerData.setLineWrap(true);
        headerData.setWrapStyleWord(true);
        JPanel headerAndSearchPanel = new JPanel(new BorderLayout());
        headerAndSearchPanel.add(new JSyntaxSearchToolBar(headerData).getToolBar(), BorderLayout.NORTH);
        headerAndSearchPanel.add(JTextScrollPane.getInstance(headerData), BorderLayout.CENTER);

        JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane.addTab(JMeterUtils.getResString("view_results_request_body"), new JScrollPane(sampleDataPanel));
        tabbedPane.addTab(JMeterUtils.getResString("view_results_request_headers"), new JScrollPane(headerAndSearchPanel));
        paneRaw.add(GuiUtils.makeScrollPane(tabbedPane));

    }

    @Override
    public void clearData() {
        setSampleData(""); //$NON-NLS-1$
        headerData.setInitialText(""); //$NON-NLS-1$
    }

    @Override
    public void setSamplerResult(Object objectResult) {
        if (objectResult instanceof SampleResult sampleResult) {
            // Don't display Request headers label if rh is null or empty
            String rh = sampleResult.getRequestHeaders();
            if (StringUtilities.isNotEmpty(rh)) {
                headerData.setInitialText(rh);
                sampleDataField.setCaretPosition(0);
            }
            String data = sampleResult.getSamplerData();
            if (StringUtilities.isNotEmpty(data)) {
                setSampleData(data);
            } else {
                // add a message when no request data (ex. Java request)
                setSampleData(JMeterUtils
                        .getResString("view_results_table_request_raw_nodata")); //$NON-NLS-1$
            }
        }
    }

    /**
     * Displays the given data, using a plain {@link JEditorPane} as a fallback
     * when the data is too large for the syntax highlighting text area.
     *
     * @param data data to display
     */
    private void setSampleData(String data) {
        if (SIMPLE_VIEW_LIMIT >= 0 && data.length() > SIMPLE_VIEW_LIMIT) {
            sampleDataField.setInitialText(""); //$NON-NLS-1$
            setTextOptimized(data);
            sampleDataLayout.show(sampleDataPanel, CARD_PLAIN);
        } else {
            sampleDataEditor.setText(""); //$NON-NLS-1$
            sampleDataField.setText(data);
            sampleDataField.setCaretPosition(0);
            sampleDataLayout.show(sampleDataPanel, CARD_SYNTAX);
        }
    }

    /**
     * Optimized way to set text based on
     * <a href="http://javatechniques.com/blog/faster-jtextpane-text-insertion-part-i/">faster text insertion</a>
     * @param data String data
     */
    private void setTextOptimized(String data) {
        Document document = sampleDataEditor.getDocument();
        Document blank = new DefaultStyledDocument();
        sampleDataEditor.setDocument(blank);
        try {
            document.insertString(0, ViewResultsFullVisualizer.wrapLongLines(data), null);
        } catch (BadLocationException ex) {
            LOGGER.error("Error inserting text", ex);
        }
        if (!(sampleDataEditor.getEditorKit() instanceof SamplerResultTab.NonWrappingPlainTextEditorKit)) {
            sampleDataEditor.setEditorKit(
                    new SamplerResultTab.NonWrappingPlainTextEditorKit(sampleDataEditor.getEditorKit()));
        }
        KerningOptimizer.INSTANCE.configureKerning(sampleDataEditor, document.getLength());
        sampleDataEditor.setDocument(document);
        sampleDataEditor.setCaretPosition(0);
    }

    @Override
    public JPanel getPanel() {
        return paneRaw;
    }

    @Override
    public String getLabel() {
        return JMeterUtils.getResString(KEY_LABEL);
    }

}
