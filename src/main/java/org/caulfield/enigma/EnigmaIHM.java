/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.caulfield.enigma;

import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Font;
import java.awt.FontFormatException;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.tree.AbstractLayoutCache;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import org.bouncycastle.util.encoders.Base64;
import org.caulfield.enigma.analyzer.FileAnalyzer;
import org.caulfield.enigma.crypto.CryptoGenerator;
import org.caulfield.enigma.crypto.EnigmaException;
import org.caulfield.enigma.crypto.x509.CRLManager;
import org.caulfield.enigma.crypto.x509.CertificateChainManager;
import org.caulfield.enigma.database.CryptoDAO;
import org.caulfield.enigma.database.EnigmaCRL;
import org.caulfield.enigma.database.EnigmaCertificate;
import org.caulfield.enigma.database.HSQLLoader;
import org.caulfield.enigma.export.ExportManager;
import org.caulfield.enigma.imp0rt.ImportManager;
import org.netbeans.swing.outline.DefaultOutlineModel;
import org.netbeans.swing.outline.Outline;
import org.netbeans.swing.outline.OutlineModel;

/**
 *
 * @author Ender
 */
public class EnigmaIHM extends javax.swing.JFrame {

	String propFile = "Enigma_fr_FR.properties";
	Properties props = new Properties();
	int posX=0,posY=0;
	/**
	 * Creates new form EnigmaIHM
	 */
	public EnigmaIHM() {
		this.setUndecorated(true);
		this.getRootPane().setBorder(BorderFactory.createMatteBorder(4, 4, 4, 4, Color.DARK_GRAY));
		

		addMouseListener(new MouseAdapter()
		{
		   public void mousePressed(MouseEvent e)
		   {
		      posX=e.getX();
		      posY=e.getY();
		   }
		});
		addMouseMotionListener(new MouseAdapter()
		{
		     public void mouseDragged(MouseEvent evt)
		     {
				//sets frame position when mouse dragged			
				setLocation (evt.getXOnScreen()-posX,evt.getYOnScreen()-posY);
							
		     }
		});
		
		initComponents();
		this.setTitle("Enigma");
		try (InputStream resourceStream = Thread.currentThread().getContextClassLoader()
				.getResourceAsStream(propFile)) {
			props.load(resourceStream);
		} catch (IOException ex) {
			Logger.getLogger(EnigmaIHM.class.getName()).log(Level.SEVERE, null, ex);
		}
		jSpinnerKeySize.setValue(new Integer(props.getProperty("defaultKeySize")));
		jTextAreaDrop.setDropTarget(new DropTarget() {
			public synchronized void drop(DropTargetDropEvent evt) {
				try {
					evt.acceptDrop(DnDConstants.ACTION_COPY);
					List<File> droppedFiles = (List<File>) evt.getTransferable()
							.getTransferData(DataFlavor.javaFileListFlavor);
					for (File file : droppedFiles) {
						jTextFieldDrop.setText(file.getAbsolutePath());
						jTextAreaDrop.setText(file.getAbsolutePath() + " loaded.");
						FileAnalyzer analyzer = new FileAnalyzer(jTextFieldDrop.getText());
						for (String dd : analyzer.getResults()) {
							jEditorPaneIdentifierResults.setText(jEditorPaneIdentifierResults.getText() + dd + "\n");
						}
					}
				} catch (Exception ex) {
					ex.printStackTrace();
				}

			}
		});
		CertificateChainManager acm = new CertificateChainManager();
		for (String AC : acm.getFullCertList()) {
			jComboBoxSignSignerCert.addItem(AC);
		}

		jTextFieldGlobalOutput.setText(System.getProperty("user.dir") + "\\");

		jComboBoxAC.addItem("None");
		for (String AC : acm.getFullACList()) {
			jComboBoxAC.addItem(AC);
		}
		jTextFieldSignFile.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(javax.swing.event.DocumentEvent de) {
				jTextFieldSignOutputFilename.setText(getFileName(jTextFieldSignFile.getText()) + ".sig");
			}

			@Override
			public void removeUpdate(javax.swing.event.DocumentEvent de) {
				jTextFieldSignOutputFilename.setText(getFileName(jTextFieldSignFile.getText()) + ".sig");
			}

			@Override
			public void changedUpdate(javax.swing.event.DocumentEvent de) {
				jTextFieldSignOutputFilename.setText(getFileName(jTextFieldSignFile.getText()) + ".sig");
			}

		});

		jTextFieldCipherFile.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(javax.swing.event.DocumentEvent de) {
				jTextFieldCipherOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".enc");
			}

			@Override
			public void removeUpdate(javax.swing.event.DocumentEvent de) {
				jTextFieldCipherOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".enc");
			}

			@Override
			public void changedUpdate(javax.swing.event.DocumentEvent de) {
				jTextFieldCipherOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".enc");
			}

		});
		ButtonGroup bG = new ButtonGroup();
		bG.add(jRadioButtonDER);
		bG.add(jRadioButtonPEM);
		bG.add(jRadioButtonPEMorDER);
		jRadioButtonPEM.setSelected(true);
		jButtonConvertPEM.setEnabled(false);
		refreshCertificateCombos();
		fillCertificateVersionObjects();
		fillAlgoObjects();
		refreshX509KeyTable();
		refreshPKObjects();
		refreshPubKObjects();
		refreshX509CertOutline();
		buildPopupMenuX509();

		outline.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

	}

	private void fillCertificateVersionObjects() {
		jComboBoxCertVersion.addItem("V1");
		jComboBoxCertVersion.addItem("V3");
		jComboBoxCertVersion.setSelectedIndex(1);
	}

	private void refreshCertificateCombos() {
		// Fill SIGNATURE Algo combobox
		try {
			jComboBoxSignSignerCert.removeAllItems();
			jComboBoxCipherCert.removeAllItems();
			HSQLLoader database = new HSQLLoader();
			ResultSet f = database.runQuery("select ID_CERT, CERTNAME from CERTIFICATES");
			while (f.next()) {
				jComboBoxSignSignerCert.addItem(f.getInt("ID_CERT") + ". " + f.getString("CERTNAME"));
				jComboBoxCipherCert.addItem(f.getInt("ID_CERT") + ". " + f.getString("CERTNAME"));
			}
		} catch (SQLException ex) {
			Logger.getLogger(EnigmaIHM.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	private void fillAlgoObjects() {
		// Fill SIGNATURE Algo combobox
		try {
			HSQLLoader database = new HSQLLoader();
			ResultSet f = database.runQuery("select ALGONAME from ALGO WHERE TYPE='SIGNATURE'");
			while (f.next()) {
				jComboBoxAlgoSign.addItem(f.getString("ALGONAME"));
				jComboBoxCertAlgo.addItem(f.getString("ALGONAME"));
			}
			jComboBoxAlgoSign.setSelectedIndex(5);
			jComboBoxCertAlgo.setSelectedIndex(5);

			f = database.runQuery("select ALGONAME from ALGO WHERE TYPE='PKCS8'");
			while (f.next()) {
				jComboBoxAlgoPk.addItem(f.getString("ALGONAME"));
			}
			jComboBoxAlgoPk.setSelectedIndex(0);

			f = database.runQuery("select ALGONAME from ALGO WHERE TYPE='CIPHER'");
			while (f.next()) {
				jComboBoxAlgoCipher.addItem(f.getString("ALGONAME"));
			}
			jComboBoxAlgoCipher.setSelectedIndex(0);
		} catch (SQLException ex) {
			Logger.getLogger(EnigmaIHM.class.getName()).log(Level.SEVERE, null, ex);
		}

	}

	private void buildPopupMenuX509Keys() {
		final JPopupMenu popupMenu = new JPopupMenu();
		JMenuItem exportKeyPEM = new JMenuItem("> Export Key as PEM");
		exportKeyPEM.addActionListener((ActionEvent e) -> {
			Integer idKey = (Integer) jTablePK.getModel().getValueAt(jTablePK.getSelectedRow(), 1);
			FileFilter ft = new FileNameExtensionFilter("Key file (.key)", "key");
			jFileChooserExportCert.resetChoosableFileFilters();
			jFileChooserExportCert.setFileFilter(ft);
			int ret = jFileChooserExportCert.showSaveDialog(this);
			if (ret == JFileChooser.APPROVE_OPTION) {
				File targetCert = jFileChooserExportCert.getSelectedFile();
				ExportManager xm = new ExportManager();
				String outRet = xm.exportKey(idKey, targetCert.getAbsolutePath());
				((DefaultListModel) jListEvents.getModel()).addElement(outRet);
			}
		});
		popupMenu.add(exportKeyPEM);
		jTablePK.setComponentPopupMenu(popupMenu);
		popupMenu.addPopupMenuListener(new PopupMenuListener() {
			@Override
			public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
				SwingUtilities.invokeLater(() -> {
					int rowAtPoint = jTablePK
							.rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), jTablePK));
					if (rowAtPoint > -1) {
						jTablePK.setRowSelectionInterval(rowAtPoint, rowAtPoint);
					}
				});
			}

			@Override
			public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
				// TODO Auto-generated method stub
			}

			@Override
			public void popupMenuCanceled(PopupMenuEvent e) {
				// TODO Auto-generated method stub
			}
		});
	}

	private void buildPopupMenuX509() {
		final JPopupMenu popupMenu = new JPopupMenu();
//        JMenuItem rootCert = new JMenuItem("+ Create New Root Certificate");
//        rootCert.addActionListener((ActionEvent e) -> {
//            System.out.println(".actionPerformed() CREATE ROOT");
//                    jTabbedPaneGenerate.setSelectedIndex(0);
//        jTabbedPaneScreens.setSelectedIndex(1);
//        
//        });
//        popupMenu.add(rootCert);
		JMenuItem subCert = new JMenuItem("+ Create New Sub Certificate");
		subCert.addActionListener((ActionEvent e) -> {
			Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
			CertificateChainManager cm = new CertificateChainManager();
			long idGeneratedCert = cm.buildIntermediateCertificate(idCert, "CN=SUBTEST,O=SUB", "");
			Integer fff = (int) (long) idGeneratedCert;
			EnigmaCertificate ddd = CryptoDAO.getEnigmaCertFromDB(fff,
					((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0)));
			((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0)).getChilds().add(ddd);
			((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0))
					.setAcserialcursor(((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0))
							.getAcserialcursor().add(BigInteger.ONE));
			final AbstractLayoutCache layout = outline.getOutlineModel().getLayout();
			TreePath path = layout.getPathForRow(outline.getSelectedRow());

//  outline.collapsePath(new TreePath(          ((EnigmaCertificate) outline.getModel().getValueAt(0, 0))));
//  outline.getOutlineModel().getLayout().setExpandedState(new TreePath(          ((EnigmaCertificate) outline.getModel().getValueAt(0, 0))), false);
//  outline.getOutlineModel().getLayout().setExpandedState(path, false);
//  outline.getOutlineModel().getTreePathSupport().collapsePath(new TreePath(          ((EnigmaCertificate) outline.getModel().getValueAt(0, 0))));
//   outline.getOutlineModel().getTreePathSupport().clear();
			outline.collapsePath(path);
			outline.expandPath(path);
//  outline.getOutlineModel().getTreePathSupport().collapsePath(path);
//  outline.getOutlineModel().getLayout().setExpandedState(path, true);
			refreshX509KeyTable();
			refreshPKObjects();
			refreshPubKObjects();
			((DefaultListModel) jListEvents.getModel())
					.addElement("Certificate " + idGeneratedCert + " successfully generated.");
		});
		popupMenu.add(subCert);
		JMenuItem userCert = new JMenuItem("+ Create New User Certificate");
		userCert.addActionListener((ActionEvent e) -> {
			Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
			CertificateChainManager cm = new CertificateChainManager();
			long idGeneratedCert = cm.buildUserCertificate(idCert, "CN=USERTEST,O=USER", "");
			Integer fff = (int) (long) idGeneratedCert;
			EnigmaCertificate ddd = CryptoDAO.getEnigmaCertFromDB(fff,
					((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0)));
			((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0)).getChilds().add(ddd);
			((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0))
					.setAcserialcursor(((EnigmaCertificate) outline.getModel().getValueAt(outline.getSelectedRow(), 0))
							.getAcserialcursor().add(BigInteger.ONE));
			final AbstractLayoutCache layout = outline.getOutlineModel().getLayout();
			TreePath path = layout.getPathForRow(outline.getSelectedRow());
			outline.collapsePath(path);
			outline.expandPath(path);
			refreshX509KeyTable();
			refreshPKObjects();
			refreshPubKObjects();
			refreshCertificateCombos();
			((DefaultListModel) jListEvents.getModel())
					.addElement("Certificate " + idGeneratedCert + " successfully generated.");
		});
		popupMenu.add(userCert);
		JMenuItem importCert = new JMenuItem("+ Import Certificate");
		importCert.addActionListener((ActionEvent e) -> {
			FileFilter ft = new FileNameExtensionFilter("Certificate file (.crt, .p7b, .cer, .der)", "crt", "p7b",
					"cert", "der");
			jFileChooserExportCert.resetChoosableFileFilters();
			jFileChooserExportCert.setFileFilter(ft);
			int ret = jFileChooserExportCert.showOpenDialog(this);
			if (ret == JFileChooser.APPROVE_OPTION) {
				File targetCert = jFileChooserExportCert.getSelectedFile();
				ImportManager xm = new ImportManager();
				String outRet = xm.importCertificate(targetCert);
				// TODO : ADD A FIND PARENT AND PRIVATE KEY AUTOMATICALLY ROUTINE
				refreshX509CertOutline();
				refreshCertificateCombos();
				((DefaultListModel) jListEvents.getModel()).addElement(outRet);
			}
		});
		popupMenu.add(importCert);
		JMenuItem exportCertPEM = new JMenuItem("> Export PEM");
		exportCertPEM.addActionListener((ActionEvent e) -> {
			Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
			FileFilter ft = new FileNameExtensionFilter("Certificate file (.crt, .cer)", "crt", "cer");
			jFileChooserExportCert.resetChoosableFileFilters();
			jFileChooserExportCert.setFileFilter(ft);
			int ret = jFileChooserExportCert.showSaveDialog(this);
			if (ret == JFileChooser.APPROVE_OPTION) {
				File targetCert = jFileChooserExportCert.getSelectedFile();
				ExportManager xm = new ExportManager();
				String outRet = xm.exportCertificate(idCert, targetCert.getAbsolutePath());
				((DefaultListModel) jListEvents.getModel()).addElement(outRet);
			}
		});
		popupMenu.add(exportCertPEM);
		JMenuItem exportCertDER = new JMenuItem("> Export DER");
		exportCertDER.addActionListener((ActionEvent e) -> {
			Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
			FileFilter ft = new FileNameExtensionFilter("Certificate file (.cer, .der, .crt)", "cer", "der", "crt");
			jFileChooserExportCert.resetChoosableFileFilters();
			jFileChooserExportCert.setFileFilter(ft);
			int ret = jFileChooserExportCert.showSaveDialog(this);
			if (ret == JFileChooser.APPROVE_OPTION) {
				File targetCert = jFileChooserExportCert.getSelectedFile();
				ExportManager xm = new ExportManager();
				String outRet = xm.exportCertificateAsDER(idCert, targetCert.getAbsolutePath());
				((DefaultListModel) jListEvents.getModel()).addElement(outRet);
			}
		});
		popupMenu.add(exportCertDER);
		JMenuItem revokeItem = new JMenuItem("/!\\ Revoke in parent CRL");
		revokeItem.addActionListener((ActionEvent e) -> {
			Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
			CRLManager crlm = new CRLManager();
			String outRet = crlm.revokeCert(idCert, "");
			((DefaultListModel) jListEvents.getModel()).addElement(outRet);
			refreshX509CertOutline();
		});
		popupMenu.add(revokeItem);
		JMenuItem deleteItem = new JMenuItem("- Delete");
		deleteItem.addActionListener((ActionEvent e) -> {
			Integer idCert = (Integer) outline.getModel().getValueAt(outline.getSelectedRow(), 1);
			String outRet = CryptoDAO.deleteCertFromDB(idCert);
			((DefaultListModel) jListEvents.getModel()).addElement(outRet);
			refreshX509CertOutline();
		});
		popupMenu.add(deleteItem);
		outline.setComponentPopupMenu(popupMenu);
		popupMenu.addPopupMenuListener(new PopupMenuListener() {
			@Override
			public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
				SwingUtilities.invokeLater(() -> {
					int rowAtPoint = outline
							.rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), outline));
					if (rowAtPoint > -1) {
						outline.setRowSelectionInterval(rowAtPoint, rowAtPoint);
					}
				});
			}

			@Override
			public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
				// TODO Auto-generated method stub
			}

			@Override
			public void popupMenuCanceled(PopupMenuEvent e) {
				// TODO Auto-generated method stub
			}
		});
	}

	private void buildPopupMenuX509CRL() {
		final JPopupMenu popupMenu = new JPopupMenu();

		JMenuItem exportCRL = new JMenuItem("> Export CRL");
		exportCRL.addActionListener((ActionEvent e) -> {
			Integer idCrl = (Integer) jTableCRL.getModel().getValueAt(jTableCRL.getSelectedRow(), 0);
			FileFilter ft = new FileNameExtensionFilter("CRL file (.crl)", "crl");
			jFileChooserExportCRL.resetChoosableFileFilters();
			jFileChooserExportCRL.setFileFilter(ft);
			int ret = jFileChooserExportCRL.showSaveDialog(this);
			if (ret == JFileChooser.APPROVE_OPTION) {
				File targetCRL = jFileChooserExportCRL.getSelectedFile();
				ExportManager xm = new ExportManager();
				String outRet = xm.exportCRL(idCrl, targetCRL.getAbsolutePath());
				((DefaultListModel) jListEvents.getModel()).addElement(outRet);
			}
		});
		popupMenu.add(exportCRL);

		jTableCRL.setComponentPopupMenu(popupMenu);
		popupMenu.addPopupMenuListener(new PopupMenuListener() {
			@Override
			public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
				SwingUtilities.invokeLater(() -> {
					int rowAtPoint = jTableCRL
							.rowAtPoint(SwingUtilities.convertPoint(popupMenu, new Point(0, 0), jTableCRL));
					if (rowAtPoint > -1) {
						jTableCRL.setRowSelectionInterval(rowAtPoint, rowAtPoint);
					}
				});
			}

			@Override
			public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
				// TODO Auto-generated method stub
			}

			@Override
			public void popupMenuCanceled(PopupMenuEvent e) {
				// TODO Auto-generated method stub
			}
		});
	}

	private void refreshX509KeyTable() {
		// Fill X509 Keys Table
		try {
			DefaultTableModel model = (DefaultTableModel) jTablePK.getModel();
			model.getDataVector().removeAllElements();
			model.fireTableDataChanged();
			HSQLLoader database = new HSQLLoader();
			ResultSet f = database
					.runQuery("select ID_KEY,KEYNAME,KEYTYPE,ALGO, SHA256,ID_ASSOCIATED_KEY from X509KEYS");
			jTablePK.getColumnModel().getColumn(0).setCellRenderer(jTablePK.getDefaultRenderer(ImageIcon.class));
			jTablePK.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
			DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
			centerRenderer.setHorizontalAlignment(JLabel.CENTER);
			jTablePK.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
			jTablePK.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
			jTablePK.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
			jTablePK.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
			jTablePK.getColumnModel().getColumn(0).setPreferredWidth(30);
			jTablePK.getColumnModel().getColumn(1).setPreferredWidth(40);
			jTablePK.getColumnModel().getColumn(2).setPreferredWidth(140);
			jTablePK.getColumnModel().getColumn(3).setPreferredWidth(100);
			jTablePK.getColumnModel().getColumn(4).setPreferredWidth(100);
			jTablePK.getColumnModel().getColumn(5).setPreferredWidth(460);
			jTablePK.getColumnModel().getColumn(6).setPreferredWidth(100);
			while (f.next()) {
				ImageIcon icon = null;
				if (1 == f.getInt("KEYTYPE")) {
					icon = new ImageIcon(getClass().getResource("/key.png"));
				} else {
					icon = new ImageIcon(getClass().getResource("/keypub.png"));
				}
				model.addRow(new Object[] { icon, f.getInt("ID_KEY"), f.getString("KEYNAME"),
						f.getInt("KEYTYPE") == 1 ? "Private" : "Public", f.getString("ALGO"), f.getString("SHA256"),
						f.getInt("ID_ASSOCIATED_KEY") });
			}
		} catch (SQLException ex) {
			Logger.getLogger(EnigmaIHM.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	private void refreshX509CertOutline() {
		// Fill X509 Certificates Outline
		TreeModel treeMdl = new CertificateTreeModel(CryptoDAO.getEnigmaCertTreeFromDB());
		OutlineModel mdl = DefaultOutlineModel.createOutlineModel(treeMdl, new CertificateRowModel(), true,
				"Certificates");
		outline.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		outline = new Outline();
		outline.setRenderDataProvider(new CertificateDataProvider());
		outline.setRootVisible(false);
		outline.setModel(mdl);
		jScrollPane1.setViewportView(outline);

		outline.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
//        DefaultTableCellRenderer redRenderer = new DefaultTableCellRenderer();
//        redRenderer.setForeground(new Color(230, 76, 76));
//        redRenderer.setHorizontalAlignment(JLabel.CENTER);
		DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
		centerRenderer.setHorizontalAlignment(JLabel.CENTER);
		outline.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
		outline.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
		outline.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
		outline.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
		outline.getColumnModel().getColumn(7).setCellRenderer(centerRenderer);
		outline.getColumnModel().getColumn(8).setCellRenderer(centerRenderer);
		outline.getColumnModel().getColumn(9).setCellRenderer(centerRenderer);
		outline.getColumnModel().getColumn(10).setCellRenderer(centerRenderer);
		outline.getColumnModel().getColumn(0).setPreferredWidth(220);
		outline.getColumnModel().getColumn(1).setPreferredWidth(30);
		outline.getColumnModel().getColumn(2).setPreferredWidth(240);
		outline.getColumnModel().getColumn(3).setPreferredWidth(260);
		outline.getColumnModel().getColumn(4).setPreferredWidth(140);
		outline.getColumnModel().getColumn(5).setPreferredWidth(100);
		outline.getColumnModel().getColumn(6).setPreferredWidth(100);
		outline.getColumnModel().getColumn(7).setPreferredWidth(60);
		outline.getColumnModel().getColumn(8).setPreferredWidth(60);
		outline.getColumnModel().getColumn(9).setPreferredWidth(100);
		outline.getColumnModel().getColumn(10).setPreferredWidth(100);
		buildPopupMenuX509();
		outline.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
			@Override
			public void valueChanged(ListSelectionEvent e) {
				int row = outline.getSelectedRow();
				EnigmaCertificate f = (EnigmaCertificate) outline.getValueAt(row, 0);
				if (!e.getValueIsAdjusting()) {
					refreshCRLTable(f.getId_cert());
				}
			}
		});
	}

	private void refreshCRLTable(Integer id_cert) {
		System.out.println("org.caulfield.enigma.EnigmaIHM.refreshCRLTable()" + id_cert);
		ArrayList<EnigmaCRL> crlList = CryptoDAO.getCRLforCertFromDB(id_cert);
		DefaultTableModel model = (DefaultTableModel) jTableCRL.getModel();
		model.getDataVector().removeAllElements();
		model.fireTableDataChanged();
		TableCellRenderer tableCellRenderer = new DefaultTableCellRenderer() {
			SimpleDateFormat f = new SimpleDateFormat("dd/MM/yyyy");

			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
					boolean hasFocus, int row, int column) {
				if (value instanceof Date) {
					value = f.format(value);
				}
				JLabel parent = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row,
						column);
				System.out.println(".getTableCellRendererComponent()" + row + "-" + parent.getFont());
				System.out.println(".getTableCellRendererComponent()" + jTableCRL.getRowCount());

				if (row == jTableCRL.getRowCount() - 1) {
					System.out.println(".getTableCellRendererComponent() update font");
					parent.setFont(parent.getFont().deriveFont(Font.BOLD));
				}
				return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
			}
		};
		((DefaultTableCellRenderer) tableCellRenderer).setHorizontalAlignment(JLabel.CENTER);
		jTableCRL.getColumnModel().getColumn(0).setCellRenderer(tableCellRenderer);
		jTableCRL.getColumnModel().getColumn(1).setCellRenderer(tableCellRenderer);
		jTableCRL.getColumnModel().getColumn(2).setCellRenderer(tableCellRenderer);
		jTableCRL.getColumnModel().getColumn(0).setPreferredWidth(30);
		jTableCRL.getColumnModel().getColumn(1).setPreferredWidth(60);
		jTableCRL.getColumnModel().getColumn(2).setPreferredWidth(60);

		for (EnigmaCRL crl : crlList) {
			model.addRow(new Object[] { crl.getIdcrl(), crl.getStartdate(), crl.getEnddate() });
		}
		buildPopupMenuX509CRL();
	}

	private void refreshPKObjects() {

		// Fill PK Keys combobox
		try {
			jComboBoxPubPK.removeAllItems();
			jComboBoxCSRPk.removeAllItems();
			jComboBoxSignPK.removeAllItems();
			jComboBoxCertPk.removeAllItems();
			jComboBoxCipher.removeAllItems();
			HSQLLoader database = new HSQLLoader();
			ResultSet f = database.runQuery("select ID_KEY,KEYNAME,ALGO from X509KEYS WHERE KEYTYPE=1");
			while (f.next()) {
				jComboBoxPubPK
						.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
				jComboBoxCSRPk
						.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
				jComboBoxSignPK
						.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
				jComboBoxCertPk
						.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
				jComboBoxCipher
						.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
			}
			buildPopupMenuX509Keys();
		} catch (SQLException ex) {
			Logger.getLogger(EnigmaIHM.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	private void refreshPubKObjects() {
		// Fill PK Keys combobox
		try {
			jComboBoxCertPubK.removeAllItems();
			jComboBoxCSRPubK.removeAllItems();
			HSQLLoader database = new HSQLLoader();
			ResultSet f = database.runQuery("select ID_KEY,KEYNAME,ALGO from X509KEYS WHERE KEYTYPE=2");
			while (f.next()) {
				jComboBoxCertPubK
						.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
				jComboBoxCSRPubK
						.addItem(f.getInt("ID_KEY") + ". " + f.getString("KEYNAME") + " (" + f.getString("ALGO") + ")");
			}
			buildPopupMenuX509Keys();
		} catch (SQLException ex) {
			Logger.getLogger(EnigmaIHM.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	private String getFileName(String str) {
		String base = str.substring(str.lastIndexOf('\\') + 1);

		return base;
	}

	/**
	 * This method is called from within the constructor to initialize the form.
	 * WARNING: Do NOT modify this code. The content of this method is always
	 * regenerated by the Form Editor.
	 */
	@SuppressWarnings("unchecked")
	// <editor-fold defaultstate="collapsed" desc="Generated
	// Code">//GEN-BEGIN:initComponents
	private void initComponents() {

		jFileChooserDirectoriesOnly = new javax.swing.JFileChooser();
		jFileChooserFileOnly = new javax.swing.JFileChooser();
		jFrameAbout = new javax.swing.JFrame();
		jButton1 = new javax.swing.JButton();
		jLabel49 = new javax.swing.JLabel();
		jLabel48 = new javax.swing.JLabel();
		jLabel50 = new javax.swing.JLabel();
		jFrameSignature = new javax.swing.JFrame();
		jPanelSignature = new javax.swing.JPanel();
		jLabel53 = new javax.swing.JLabel();
		jScrollPane6 = new javax.swing.JScrollPane();
		jTextArea2 = new javax.swing.JTextArea();
		jButton4 = new javax.swing.JButton();
		jFrameX509vsPGP = new javax.swing.JFrame();
		jPanelX509vsPGP = new javax.swing.JPanel();
		jScrollPane7 = new javax.swing.JScrollPane();
		jTextArea3 = new javax.swing.JTextArea();
		jButton5 = new javax.swing.JButton();
		jDialogFileImport = new javax.swing.JDialog();
		jLabel62 = new javax.swing.JLabel();
		jTextFieldImportKeyName = new javax.swing.JTextField();
		jButtonKeyName = new javax.swing.JButton();
		jLabel63 = new javax.swing.JLabel();
		jTextFieldImportKeyFile = new javax.swing.JTextField();
		jButtonImportKey = new javax.swing.JButton();
		jDialogFileImportPublic = new javax.swing.JDialog();
		jLabel64 = new javax.swing.JLabel();
		jTextFieldImportKeyName1 = new javax.swing.JTextField();
		jButtonKeyName1 = new javax.swing.JButton();
		jLabel65 = new javax.swing.JLabel();
		jTextFieldImportKeyFile1 = new javax.swing.JTextField();
		jButtonImportKey1 = new javax.swing.JButton();
		jFileChooserExportCert = new javax.swing.JFileChooser();
		jFileChooserExportCRL = new javax.swing.JFileChooser();
		jPanelPGPKeyring = new javax.swing.JPanel();
		jLabel56 = new javax.swing.JLabel();
		jPanelScenarios = new javax.swing.JPanel();
		jLabel18 = new javax.swing.JLabel();
		jButton10 = new javax.swing.JButton();
		jButton11 = new javax.swing.JButton();
		jButton12 = new javax.swing.JButton();
		jButton13 = new javax.swing.JButton();
		jButton14 = new javax.swing.JButton();
		jLabel58 = new javax.swing.JLabel();
		jButton15 = new javax.swing.JButton();
		jButton16 = new javax.swing.JButton();
		jButtonDashPGP = new javax.swing.JButton();
		jButtonDashScenarios = new javax.swing.JButton();
		jTabbedPaneScreens = new javax.swing.JTabbedPane();
		jPanelDashboard = new javax.swing.JPanel();
		jButtonDashGenerate = new javax.swing.JButton();
		jButtonDashTransform = new javax.swing.JButton();
		jButtonDashAnalyze = new javax.swing.JButton();
		jButtonDashConvert = new javax.swing.JButton();
		jButtonDashX509 = new javax.swing.JButton();
		jButtonDashAbout = new javax.swing.JButton();
		jLabel5 = new javax.swing.JLabel();
		jLabel5.setFont(new Font("Tahoma", Font.PLAIN, 82));
		jLabel25 = new javax.swing.JLabel();
		jLabel25.setFont(new Font("MicroSquare", Font.BOLD | Font.ITALIC, 82));
		jLabel25.setForeground(new Color(51, 51, 51));
		jLabel25.setText("ENIGMA");
		jPanelACManagement = new javax.swing.JPanel();
		jPanel19 = new javax.swing.JPanel();
		jScrollPane1 = new javax.swing.JScrollPane();
		outline = new org.netbeans.swing.outline.Outline();
		jPanel20 = new javax.swing.JPanel();
		jScrollPane9 = new javax.swing.JScrollPane();
		jTablePK = new javax.swing.JTable();
		jPanel21 = new javax.swing.JPanel();
		jScrollPane2 = new javax.swing.JScrollPane();
		jTableCRL = new javax.swing.JTable();
		jTabbedPaneGenerate = new javax.swing.JTabbedPane();
		jPanel2 = new javax.swing.JPanel();
		jPanel1 = new javax.swing.JPanel();
		jTextFieldKeystorePW = new javax.swing.JTextField();
		jTextFieldPKCS8PW = new javax.swing.JTextField();
		jLabel1 = new javax.swing.JLabel();
		jLabel2 = new javax.swing.JLabel();
		jLabel3 = new javax.swing.JLabel();
		jTextFieldCN = new javax.swing.JTextField();
		jSpinnerKeySize = new javax.swing.JSpinner();
		jLabel4 = new javax.swing.JLabel();
		jComboBoxAC = new javax.swing.JComboBox<>();
		jLabel6 = new javax.swing.JLabel();
		jLabel9 = new javax.swing.JLabel();
		jComboBoxAlgoP12 = new javax.swing.JComboBox<>();
		jLabel10 = new javax.swing.JLabel();
		jSpinnerP12Expo = new javax.swing.JSpinner();
		jLabel11 = new javax.swing.JLabel();
		jSliderP12Certainty = new javax.swing.JSlider();
		jCheckBoxP12Expo = new javax.swing.JCheckBox();
		jCheckBoxP12Certainty = new javax.swing.JCheckBox();
		jButtonPKCS12Generate = new javax.swing.JButton();
		jDateChooserP12Expiry = new com.toedter.calendar.JDateChooser();
		jLabel31 = new javax.swing.JLabel();
		jLabel40 = new javax.swing.JLabel();
		jTextFieldP12TargetFilename = new javax.swing.JTextField();
		jCheckBoxP12Write = new javax.swing.JCheckBox();
		jPanel3 = new javax.swing.JPanel();
		jButtonPkGenerate = new javax.swing.JButton();
		jLabel12 = new javax.swing.JLabel();
		jSpinnerKeySizePkSize = new javax.swing.JSpinner();
		jTextFieldPkTargetFilename = new javax.swing.JTextField();
		jSliderPkCertainty = new javax.swing.JSlider();
		jLabel14 = new javax.swing.JLabel();
		jCheckBoxPkCertainty = new javax.swing.JCheckBox();
		jLabel15 = new javax.swing.JLabel();
		jSpinnerPkExpo = new javax.swing.JSpinner();
		jCheckBoxPkExpo = new javax.swing.JCheckBox();
		jComboBoxAlgoPk = new javax.swing.JComboBox<>();
		jLabel16 = new javax.swing.JLabel();
		jTextFieldPkPw = new javax.swing.JTextField();
		jLabel17 = new javax.swing.JLabel();
		jLabel27 = new javax.swing.JLabel();
		jLabel59 = new javax.swing.JLabel();
		jTextFieldPkTargetKeyName = new javax.swing.JTextField();
		jPanel4 = new javax.swing.JPanel();
		jButtonCertGenerate = new javax.swing.JButton();
		jLabel19 = new javax.swing.JLabel();
		jTextFieldCertCN = new javax.swing.JTextField();
		jLabel20 = new javax.swing.JLabel();
		jTextFieldCertPkPw = new javax.swing.JTextField();
		jLabel21 = new javax.swing.JLabel();
		jLabel22 = new javax.swing.JLabel();
		jButtonBrowseCertPub = new javax.swing.JButton();
		jButtonBrowseCertPk = new javax.swing.JButton();
		jLabel28 = new javax.swing.JLabel();
		jTextFieldCertTargetFilename = new javax.swing.JTextField();
		jDateChooserExpiry = new com.toedter.calendar.JDateChooser();
		jLabel30 = new javax.swing.JLabel();
		jComboBoxCertPk = new javax.swing.JComboBox<>();
		jComboBoxCertPubK = new javax.swing.JComboBox<>();
		jComboBoxCertAlgo = new javax.swing.JComboBox<>();
		jLabel61 = new javax.swing.JLabel();
		jLabel66 = new javax.swing.JLabel();
		jComboBoxCertVersion = new javax.swing.JComboBox<>();
		jLabel67 = new javax.swing.JLabel();
		jTextFieldPubTargetCertName = new javax.swing.JTextField();
		jPanel5 = new javax.swing.JPanel();
		jButtonPubGenerate = new javax.swing.JButton();
		jLabel23 = new javax.swing.JLabel();
		jLabel24 = new javax.swing.JLabel();
		jTextFieldPubPrivkeyPW = new javax.swing.JTextField();
		jLabel26 = new javax.swing.JLabel();
		jTextFieldPubTargetFilename = new javax.swing.JTextField();
		jComboBoxPubPK = new javax.swing.JComboBox<>();
		jLabel60 = new javax.swing.JLabel();
		jTextFieldPubTargetKeyName = new javax.swing.JTextField();
		jButtonBrowsePubPk = new javax.swing.JButton();
		jPanel6 = new javax.swing.JPanel();
		jButtonCSRGenerate = new javax.swing.JButton();
		jLabel32 = new javax.swing.JLabel();
		jButtonBrowseP10Pk = new javax.swing.JButton();
		jLabel34 = new javax.swing.JLabel();
		jTextFieldP10PkPw = new javax.swing.JTextField();
		jLabel36 = new javax.swing.JLabel();
		jTextFieldP10CN = new javax.swing.JTextField();
		jLabel37 = new javax.swing.JLabel();
		jTextFieldP10TargetFilename = new javax.swing.JTextField();
		jCheckBoxP10PubKey = new javax.swing.JCheckBox();
		jComboBoxCSRPk = new javax.swing.JComboBox<>();
		jComboBoxCSRPubK = new javax.swing.JComboBox<>();
		jButtonBrowseP10PubK = new javax.swing.JButton();
		jPanel14 = new javax.swing.JPanel();
		jLabel57 = new javax.swing.JLabel();
		jPanelTransform = new javax.swing.JPanel();
		jTabbedPane1 = new javax.swing.JTabbedPane();
		jPanel9 = new javax.swing.JPanel();
		jPanel11 = new javax.swing.JPanel();
		jLabel41 = new javax.swing.JLabel();
		jLabel42 = new javax.swing.JLabel();
		jTextFieldSignFile = new javax.swing.JTextField();
		jButtonBrowseSignFile = new javax.swing.JButton();
		jComboBoxSignPK = new javax.swing.JComboBox<>();
		jLabel43 = new javax.swing.JLabel();
		jComboBoxAlgoSign = new javax.swing.JComboBox<>();
		jButtonSign = new javax.swing.JButton();
		jLabel46 = new javax.swing.JLabel();
		jTextFieldSignPkPassword = new javax.swing.JTextField();
		jCheckBox2 = new javax.swing.JCheckBox();
		jLabel52 = new javax.swing.JLabel();
		jComboBoxSignSignerCert = new javax.swing.JComboBox<>();
		jLabel44 = new javax.swing.JLabel();
		jTextFieldSignOutputFilename = new javax.swing.JTextField();
		jPanel13 = new javax.swing.JPanel();
		jLabel47 = new javax.swing.JLabel();
		jTextFieldCipherFile = new javax.swing.JTextField();
		jButtonBrowseCipherFile = new javax.swing.JButton();
		jButtonCipher = new javax.swing.JButton();
		jComboBoxAlgoCipher = new javax.swing.JComboBox<>();
		jLabel51 = new javax.swing.JLabel();
		jLabel69 = new javax.swing.JLabel();
		jTextFieldCipherOutputFilename = new javax.swing.JTextField();
		jCheckBoxCustomCipher = new javax.swing.JCheckBox();
		jLabel70 = new javax.swing.JLabel();
		jComboBoxCipherCert = new javax.swing.JComboBox<>();
		jPanel15 = new javax.swing.JPanel();
		jLabel45 = new javax.swing.JLabel();
		jTextFieldSignFile1 = new javax.swing.JTextField();
		jButtonBrowseSignFile1 = new javax.swing.JButton();
		jLabel73 = new javax.swing.JLabel();
		jComboBoxCipher = new javax.swing.JComboBox<>();
		jLabel74 = new javax.swing.JLabel();
		jTextFieldSignPkPassword1 = new javax.swing.JTextField();
		jLabel75 = new javax.swing.JLabel();
		jTextFieldDecryptOutputFilename = new javax.swing.JTextField();
		jCheckBoxCustomDecrypt = new javax.swing.JCheckBox();
		jButtonDecrypt = new javax.swing.JButton();
		jPanel16 = new javax.swing.JPanel();
		jCheckBoxCustomVerify = new javax.swing.JCheckBox();
		jTextFieldVerifyOutputFilename = new javax.swing.JTextField();
		jLabel71 = new javax.swing.JLabel();
		jComboBoxVerifyCert = new javax.swing.JComboBox<>();
		jLabel72 = new javax.swing.JLabel();
		jLabel68 = new javax.swing.JLabel();
		jTextFieldVerifyFile = new javax.swing.JTextField();
		jButtonBrowseVerifyFile = new javax.swing.JButton();
		jButtonValidate = new javax.swing.JButton();
		jCheckBoxCustomVerifyTryAll = new javax.swing.JCheckBox();
		jButtonVerify = new javax.swing.JButton();
		jPanel10 = new javax.swing.JPanel();
		jPanelAnalyze = new javax.swing.JPanel();
		jLabel7 = new javax.swing.JLabel();
		jTextFieldDrop = new javax.swing.JTextField();
		jButton7 = new javax.swing.JButton();
		jScrollPane3 = new javax.swing.JScrollPane();
		jEditorPaneIdentifierResults = new javax.swing.JEditorPane();
		jLabel8 = new javax.swing.JLabel();
		jPanel12 = new javax.swing.JPanel();
		jScrollPane4 = new javax.swing.JScrollPane();
		jTextAreaDrop = new javax.swing.JTextArea();
		jButton8 = new javax.swing.JButton();
		jPanel17 = new javax.swing.JPanel();
		jPanel18 = new javax.swing.JPanel();
		jScrollPane5 = new javax.swing.JScrollPane();
		jTextAreaOriginalData = new javax.swing.JTextArea();
		jScrollPane8 = new javax.swing.JScrollPane();
		jTextAreaBase64Data = new javax.swing.JTextArea();
		jLabel54 = new javax.swing.JLabel();
		jLabel55 = new javax.swing.JLabel();
		jButtonEncodeBase64 = new javax.swing.JButton();
		jButtonDecodeBase64 = new javax.swing.JButton();
		jPanel7 = new javax.swing.JPanel();
		jRadioButtonDER = new javax.swing.JRadioButton();
		jLabel33 = new javax.swing.JLabel();
		jTextFieldConvertSourceFile = new javax.swing.JTextField();
		jButtonConvertSourceFile = new javax.swing.JButton();
		jRadioButtonPEM = new javax.swing.JRadioButton();
		jRadioButtonPEMorDER = new javax.swing.JRadioButton();
		jButtonConvertPEM = new javax.swing.JButton();
		jButtonConvertDER = new javax.swing.JButton();
		jPanelEvents = new javax.swing.JPanel();
		jProgressBarEnigma = new javax.swing.JProgressBar();
		jScrollPaneForEvents = new javax.swing.JScrollPane();
		jListEvents = new javax.swing.JList<>();
		jTextFieldGlobalOutput = new javax.swing.JTextField();
		jLabel38 = new javax.swing.JLabel();
		jButtonBrowseGlobalOutput = new javax.swing.JButton();
		jButtonBrowseGlobalOutput1 = new javax.swing.JButton();

		jFileChooserDirectoriesOnly.setDialogTitle("");
		jFileChooserDirectoriesOnly.setFileSelectionMode(javax.swing.JFileChooser.DIRECTORIES_ONLY);

		jFileChooserFileOnly.setDialogTitle("");

		jFrameAbout.setTitle("About Enigma");
		jFrameAbout.setAlwaysOnTop(true);
		jFrameAbout.setResizable(false);
		jFrameAbout.setSize(new java.awt.Dimension(565, 709));

		jButton1.setBackground(new java.awt.Color(204, 255, 204));
		jButton1.setFont(new java.awt.Font("Gulim", 1, 14)); // NOI18N
		jButton1.setText("I see !");
		jButton1.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton1ActionPerformed(evt);
			}
		});

		jLabel49.setIcon(new javax.swing.ImageIcon(getClass().getResource("/enigma500.png"))); // NOI18N

		jLabel48.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
		jLabel48.setText("Author : Philippe BAKHTIARI");

		jLabel50.setFont(new java.awt.Font("Tahoma", 0, 20)); // NOI18N
		jLabel50.setText("Enigma version 1.04a ");

		javax.swing.GroupLayout jFrameAboutLayout = new javax.swing.GroupLayout(jFrameAbout.getContentPane());
		jFrameAbout.getContentPane().setLayout(jFrameAboutLayout);
		jFrameAboutLayout.setHorizontalGroup(jFrameAboutLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jFrameAboutLayout.createSequentialGroup().addGap(0, 0, Short.MAX_VALUE).addComponent(jLabel50)
								.addGap(178, 178, 178))
				.addGroup(jFrameAboutLayout.createSequentialGroup().addGroup(jFrameAboutLayout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jFrameAboutLayout.createSequentialGroup().addGap(36, 36, 36).addComponent(jLabel49))
						.addGroup(jFrameAboutLayout.createSequentialGroup().addGap(200, 200, 200).addComponent(jLabel48,
								javax.swing.GroupLayout.PREFERRED_SIZE, 165, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGroup(jFrameAboutLayout.createSequentialGroup().addGap(154, 154, 154).addComponent(jButton1,
								javax.swing.GroupLayout.PREFERRED_SIZE, 241, javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addContainerGap(29, Short.MAX_VALUE)));
		jFrameAboutLayout
				.setVerticalGroup(jFrameAboutLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jFrameAboutLayout.createSequentialGroup().addGap(27, 27, 27).addComponent(jLabel50)
								.addGap(18, 18, 18).addComponent(jLabel49)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 48,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGap(18, 18, 18).addComponent(jLabel48).addContainerGap(47, Short.MAX_VALUE)));

		jFrameSignature.setMinimumSize(new java.awt.Dimension(780, 300));

		jPanelSignature.setBorder(javax.swing.BorderFactory.createTitledBorder("Signature de fichier"));

		jLabel53.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
		jLabel53.setIcon(new javax.swing.ImageIcon(getClass().getResource("/X509sig.png"))); // NOI18N
		jLabel53.setToolTipText("");

		jTextArea2.setBackground(javax.swing.UIManager.getDefaults().getColor("Button.background"));
		jTextArea2.setColumns(20);
		jTextArea2.setFont(new java.awt.Font("Tahoma", 0, 11)); // NOI18N
		jTextArea2.setRows(5);
		jTextArea2.setText(
				"Advantages of X.509 Signatures\n\nIt is much easier to verify that the key that signed the file is really ours (not attacker’s).\nYou do not have to download or install any extra software to verify an X.509 signature (see below).\nYou do not have to download and import our public key (it is embedded in the signed file).\nYou do not have to download any separate signature file (the signature is embedded in the signed file).\n\nAdvantages of PGP Signatures\n\nThey do not depend on any certificate authority (which might be e.g. infiltrated or controlled by an adversary, or be untrustworthy for other reasons).");
		jScrollPane6.setViewportView(jTextArea2);

		javax.swing.GroupLayout jPanelSignatureLayout = new javax.swing.GroupLayout(jPanelSignature);
		jPanelSignature.setLayout(jPanelSignatureLayout);
		jPanelSignatureLayout.setHorizontalGroup(jPanelSignatureLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanelSignatureLayout.createSequentialGroup().addContainerGap(30, Short.MAX_VALUE)
						.addGroup(jPanelSignatureLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
										jPanelSignatureLayout.createSequentialGroup()
												.addComponent(jScrollPane6, javax.swing.GroupLayout.PREFERRED_SIZE, 728,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addContainerGap())
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanelSignatureLayout
										.createSequentialGroup().addComponent(jLabel53).addGap(139, 139, 139)))));
		jPanelSignatureLayout
				.setVerticalGroup(jPanelSignatureLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanelSignatureLayout.createSequentialGroup().addContainerGap()
								.addComponent(jScrollPane6, javax.swing.GroupLayout.PREFERRED_SIZE, 145,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jLabel53)));

		jButton4.setBackground(new java.awt.Color(204, 255, 204));
		jButton4.setFont(new java.awt.Font("Gulim", 1, 14)); // NOI18N
		jButton4.setText("I see !");
		jButton4.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton4ActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jFrameSignatureLayout = new javax.swing.GroupLayout(jFrameSignature.getContentPane());
		jFrameSignature.getContentPane().setLayout(jFrameSignatureLayout);
		jFrameSignatureLayout.setHorizontalGroup(jFrameSignatureLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanelSignature, javax.swing.GroupLayout.DEFAULT_SIZE,
						javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jFrameSignatureLayout.createSequentialGroup()
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE).addComponent(jButton4,
								javax.swing.GroupLayout.PREFERRED_SIZE, 241, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(268, 268, 268)));
		jFrameSignatureLayout.setVerticalGroup(
				jFrameSignatureLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
						javax.swing.GroupLayout.Alignment.TRAILING,
						jFrameSignatureLayout.createSequentialGroup()
								.addComponent(jPanelSignature, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGap(18, 18, 18)
								.addComponent(jButton4, javax.swing.GroupLayout.PREFERRED_SIZE, 48,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		jFrameX509vsPGP.setMinimumSize(new java.awt.Dimension(780, 300));

		jPanelX509vsPGP.setBorder(javax.swing.BorderFactory.createTitledBorder("X509 vs PGP"));

		jTextArea3.setBackground(javax.swing.UIManager.getDefaults().getColor("Button.background"));
		jTextArea3.setColumns(20);
		jTextArea3.setFont(new java.awt.Font("Tahoma", 0, 11)); // NOI18N
		jTextArea3.setRows(5);
		jTextArea3.setText(
				"Advantages of X.509 Signatures\n\nIt is much easier to verify that the key that signed the file is really ours (not attacker’s).\nYou do not have to download or install any extra software to verify an X.509 signature (see below).\nYou do not have to download and import our public key (it is embedded in the signed file).\nYou do not have to download any separate signature file (the signature is embedded in the signed file).\n\nAdvantages of PGP Signatures\n\nThey do not depend on any certificate authority (which might be e.g. infiltrated or controlled by an adversary, or be untrustworthy for other reasons).");
		jScrollPane7.setViewportView(jTextArea3);

		javax.swing.GroupLayout jPanelX509vsPGPLayout = new javax.swing.GroupLayout(jPanelX509vsPGP);
		jPanelX509vsPGP.setLayout(jPanelX509vsPGPLayout);
		jPanelX509vsPGPLayout.setHorizontalGroup(jPanelX509vsPGPLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 768, Short.MAX_VALUE)
				.addGroup(jPanelX509vsPGPLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanelX509vsPGPLayout.createSequentialGroup().addGap(4, 4, 4)
								.addComponent(jScrollPane7).addGap(4, 4, 4))));
		jPanelX509vsPGPLayout.setVerticalGroup(jPanelX509vsPGPLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 180, Short.MAX_VALUE)
				.addGroup(jPanelX509vsPGPLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanelX509vsPGPLayout.createSequentialGroup().addContainerGap()
								.addComponent(jScrollPane7, javax.swing.GroupLayout.PREFERRED_SIZE, 158,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))));

		jButton5.setBackground(new java.awt.Color(204, 255, 204));
		jButton5.setFont(new java.awt.Font("Gulim", 1, 14)); // NOI18N
		jButton5.setText("I see !");
		jButton5.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton5ActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jFrameX509vsPGPLayout = new javax.swing.GroupLayout(jFrameX509vsPGP.getContentPane());
		jFrameX509vsPGP.getContentPane().setLayout(jFrameX509vsPGPLayout);
		jFrameX509vsPGPLayout
				.setHorizontalGroup(jFrameX509vsPGPLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jFrameX509vsPGPLayout.createSequentialGroup().addGap(267, 267, 267)
								.addComponent(jButton5, javax.swing.GroupLayout.PREFERRED_SIZE, 241,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addContainerGap(272, Short.MAX_VALUE))
						.addGroup(jFrameX509vsPGPLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jPanelX509vsPGP, javax.swing.GroupLayout.Alignment.TRAILING,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE)));
		jFrameX509vsPGPLayout.setVerticalGroup(
				jFrameX509vsPGPLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(
								javax.swing.GroupLayout.Alignment.TRAILING,
								jFrameX509vsPGPLayout
										.createSequentialGroup().addContainerGap(224, Short.MAX_VALUE)
										.addComponent(jButton5, javax.swing.GroupLayout.PREFERRED_SIZE, 48,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(28, 28, 28))
						.addGroup(jFrameX509vsPGPLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jFrameX509vsPGPLayout.createSequentialGroup()
										.addComponent(jPanelX509vsPGP, javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(0, 98, Short.MAX_VALUE))));

		jDialogFileImport.setTitle("Import Key");
		jDialogFileImport.setAlwaysOnTop(true);
		jDialogFileImport.setMinimumSize(new java.awt.Dimension(352, 125));
		jDialogFileImport.setModalityType(java.awt.Dialog.ModalityType.APPLICATION_MODAL);
		jDialogFileImport.setSize(new java.awt.Dimension(352, 125));

		jLabel62.setText("Key Name :");

		jTextFieldImportKeyName.setText("imported_key");

		jButtonKeyName.setText("Validate");
		jButtonKeyName.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonKeyNameActionPerformed(evt);
			}
		});

		jLabel63.setText("Key File :");

		jButtonImportKey.setText("Browse..");
		jButtonImportKey.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonImportKeyActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jDialogFileImportLayout = new javax.swing.GroupLayout(
				jDialogFileImport.getContentPane());
		jDialogFileImport.getContentPane().setLayout(jDialogFileImportLayout);
		jDialogFileImportLayout.setHorizontalGroup(jDialogFileImportLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jDialogFileImportLayout.createSequentialGroup().addGap(10, 10, 10)
						.addGroup(jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel62).addComponent(jLabel63))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jTextFieldImportKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGroup(jDialogFileImportLayout.createSequentialGroup()
										.addComponent(jTextFieldImportKeyFile, javax.swing.GroupLayout.PREFERRED_SIZE,
												150, javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(6, 6, 6).addComponent(jButtonImportKey))
								.addComponent(jButtonKeyName, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addContainerGap(44, Short.MAX_VALUE)));
		jDialogFileImportLayout.setVerticalGroup(jDialogFileImportLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jDialogFileImportLayout.createSequentialGroup().addGap(11, 11, 11)
						.addGroup(jDialogFileImportLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jDialogFileImportLayout.createSequentialGroup().addGap(31, 31, 31)
										.addGroup(jDialogFileImportLayout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addGroup(jDialogFileImportLayout.createSequentialGroup()
														.addGap(1, 1, 1).addComponent(jTextFieldImportKeyFile,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE))
												.addComponent(jButtonImportKey))
										.addGap(6, 6, 6).addComponent(jButtonKeyName))
								.addGroup(jDialogFileImportLayout.createSequentialGroup()
										.addGroup(jDialogFileImportLayout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel62).addComponent(jTextFieldImportKeyName,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE))
										.addGap(15, 15, 15).addComponent(jLabel63)))
						.addContainerGap(23, Short.MAX_VALUE)));

		jDialogFileImportPublic.setTitle("Import Key");
		jDialogFileImportPublic.setAlwaysOnTop(true);
		jDialogFileImportPublic.setMinimumSize(new java.awt.Dimension(352, 125));
		jDialogFileImportPublic.setModalityType(java.awt.Dialog.ModalityType.APPLICATION_MODAL);
		jDialogFileImportPublic.setSize(new java.awt.Dimension(352, 125));

		jLabel64.setText("Key Name :");

		jTextFieldImportKeyName1.setText("imported_key");

		jButtonKeyName1.setText("Validate");
		jButtonKeyName1.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonKeyName1ActionPerformed(evt);
			}
		});

		jLabel65.setText("Key File :");

		jButtonImportKey1.setText("Browse..");
		jButtonImportKey1.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonImportKey1ActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jDialogFileImportPublicLayout = new javax.swing.GroupLayout(
				jDialogFileImportPublic.getContentPane());
		jDialogFileImportPublic.getContentPane().setLayout(jDialogFileImportPublicLayout);
		jDialogFileImportPublicLayout.setHorizontalGroup(jDialogFileImportPublicLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jDialogFileImportPublicLayout.createSequentialGroup().addGap(10, 10, 10)
						.addGroup(jDialogFileImportPublicLayout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jLabel64)
								.addComponent(jLabel65))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(jDialogFileImportPublicLayout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jTextFieldImportKeyName1, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
										.addComponent(jTextFieldImportKeyFile1, javax.swing.GroupLayout.PREFERRED_SIZE,
												150, javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(6, 6, 6).addComponent(jButtonImportKey1))
								.addComponent(jButtonKeyName1, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addContainerGap(44, Short.MAX_VALUE)));
		jDialogFileImportPublicLayout.setVerticalGroup(jDialogFileImportPublicLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jDialogFileImportPublicLayout.createSequentialGroup().addGap(11, 11, 11)
						.addGroup(jDialogFileImportPublicLayout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jDialogFileImportPublicLayout.createSequentialGroup().addGap(31, 31, 31)
										.addGroup(jDialogFileImportPublicLayout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
														.addGap(1, 1, 1).addComponent(jTextFieldImportKeyFile1,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE))
												.addComponent(jButtonImportKey1))
										.addGap(6, 6, 6).addComponent(jButtonKeyName1))
								.addGroup(jDialogFileImportPublicLayout.createSequentialGroup()
										.addGroup(jDialogFileImportPublicLayout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel64).addComponent(jTextFieldImportKeyName1,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE))
										.addGap(15, 15, 15).addComponent(jLabel65)))
						.addContainerGap(31, Short.MAX_VALUE)));

		jFileChooserExportCert.setFileFilter(null);

		jFileChooserExportCRL.setDialogTitle("");

		jPanelPGPKeyring.setEnabled(false);

		jLabel56.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
		jLabel56.setText("Coming soon ... ");

		javax.swing.GroupLayout jPanelPGPKeyringLayout = new javax.swing.GroupLayout(jPanelPGPKeyring);
		jPanelPGPKeyring.setLayout(jPanelPGPKeyringLayout);
		jPanelPGPKeyringLayout.setHorizontalGroup(
				jPanelPGPKeyringLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanelPGPKeyringLayout.createSequentialGroup().addGap(586, 586, 586)
								.addComponent(jLabel56).addContainerGap(702, Short.MAX_VALUE)));
		jPanelPGPKeyringLayout
				.setVerticalGroup(jPanelPGPKeyringLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanelPGPKeyringLayout.createSequentialGroup().addGap(293, 293, 293)
								.addComponent(jLabel56).addContainerGap(353, Short.MAX_VALUE)));

		jPanelScenarios.setEnabled(false);
		jPanelScenarios.setPreferredSize(new java.awt.Dimension(500, 544));

		jLabel18.setText("What do you want to do ?");

		jButton10.setText("I have a file and I want to sign it");

		jButton11.setText("I have a file and I want to encrypt it");

		jButton12.setText("I have a file and I don't know what it is");

		jButton13.setText("I want to create a PGP Key");

		jButton14.setText("I want to create a Certificate");

		jLabel58.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
		jLabel58.setText("Coming soon ... ");

		jButton15.setText("What is a signature ?");
		jButton15.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton15ActionPerformed(evt);
			}
		});

		jButton16.setText("Whare are the advantages of PGP and X509 ?");
		jButton16.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton16ActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanelScenariosLayout = new javax.swing.GroupLayout(jPanelScenarios);
		jPanelScenarios.setLayout(jPanelScenariosLayout);
		jPanelScenariosLayout.setHorizontalGroup(jPanelScenariosLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanelScenariosLayout.createSequentialGroup().addContainerGap()
						.addGroup(jPanelScenariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanelScenariosLayout
										.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
										.addComponent(jButton13, javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jLabel18, javax.swing.GroupLayout.Alignment.LEADING)
										.addComponent(jButton10, javax.swing.GroupLayout.Alignment.LEADING,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jButton12, javax.swing.GroupLayout.Alignment.LEADING,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jButton11, javax.swing.GroupLayout.Alignment.LEADING,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
								.addComponent(jButton14, javax.swing.GroupLayout.PREFERRED_SIZE, 221,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(26, 26, 26)
						.addGroup(jPanelScenariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jButton16, javax.swing.GroupLayout.PREFERRED_SIZE, 293,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jButton15, javax.swing.GroupLayout.PREFERRED_SIZE, 221,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel58))
						.addContainerGap(882, Short.MAX_VALUE)));
		jPanelScenariosLayout.setVerticalGroup(jPanelScenariosLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanelScenariosLayout.createSequentialGroup().addContainerGap().addComponent(jLabel18)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(jPanelScenariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jButton12).addComponent(jButton16))
						.addGap(19, 19, 19)
						.addGroup(jPanelScenariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jButton10).addComponent(jButton15))
						.addGap(12, 12, 12).addComponent(jButton11)
						.addGroup(jPanelScenariosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanelScenariosLayout.createSequentialGroup()
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(jButton13))
								.addGroup(jPanelScenariosLayout.createSequentialGroup().addGap(22, 22, 22)
										.addComponent(jLabel58)))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jButton14)
						.addContainerGap(459, Short.MAX_VALUE)));

		jButtonDashPGP.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
		jButtonDashPGP.setIcon(new javax.swing.ImageIcon(getClass().getResource("/pgp.png"))); // NOI18N
		jButtonDashPGP.setText("Trousseau PGP");
		jButtonDashPGP.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
		jButtonDashPGP.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
		jButtonDashPGP.setIconTextGap(10);
		jButtonDashPGP.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDashPGPActionPerformed(evt);
			}
		});

		jButtonDashScenarios.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
		jButtonDashScenarios.setIcon(new javax.swing.ImageIcon(getClass().getResource("/scenario.png"))); // NOI18N
		jButtonDashScenarios.setText("Scenarios");
		jButtonDashScenarios.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
		jButtonDashScenarios.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
		jButtonDashScenarios.setIconTextGap(10);
		jButtonDashScenarios.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDashScenariosActionPerformed(evt);
			}
		});

		setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
		setResizable(false);
		setSize(new java.awt.Dimension(1427, 846));

		jTabbedPaneScreens.setFont(new java.awt.Font("Segoe UI Symbol", 0, 14)); // NOI18N
		jTabbedPaneScreens.setMaximumSize(new java.awt.Dimension(1437, 693));
		jTabbedPaneScreens.setMinimumSize(new java.awt.Dimension(1437, 693));
		jTabbedPaneScreens.setPreferredSize(new java.awt.Dimension(1437, 693));

		jPanelDashboard.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Choisissez une activité :",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jButtonDashGenerate.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
		jButtonDashGenerate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/create.png"))); // NOI18N
		jButtonDashGenerate.setText("Générer");
		jButtonDashGenerate.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
		jButtonDashGenerate.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
		jButtonDashGenerate.setIconTextGap(10);
		jButtonDashGenerate.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDashGenerateActionPerformed(evt);
			}
		});

		jButtonDashTransform.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
		jButtonDashTransform.setIcon(new javax.swing.ImageIcon(getClass().getResource("/transform.png"))); // NOI18N
		jButtonDashTransform.setText("Transformer");
		jButtonDashTransform.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
		jButtonDashTransform.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
		jButtonDashTransform.setIconTextGap(10);
		jButtonDashTransform.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDashTransformActionPerformed(evt);
			}
		});

		jButtonDashAnalyze.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
		jButtonDashAnalyze.setIcon(new javax.swing.ImageIcon(getClass().getResource("/analyze3.png"))); // NOI18N
		jButtonDashAnalyze.setText("Analyser");
		jButtonDashAnalyze.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
		jButtonDashAnalyze.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
		jButtonDashAnalyze.setIconTextGap(10);
		jButtonDashAnalyze.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDashAnalyzeActionPerformed(evt);
			}
		});

		jButtonDashConvert.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
		jButtonDashConvert.setIcon(new javax.swing.ImageIcon(getClass().getResource("/convert.png"))); // NOI18N
		jButtonDashConvert.setText("Convertir");
		jButtonDashConvert.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
		jButtonDashConvert.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
		jButtonDashConvert.setIconTextGap(10);
		jButtonDashConvert.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDashConvertActionPerformed(evt);
			}
		});

		jButtonDashX509.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
		jButtonDashX509.setIcon(new javax.swing.ImageIcon(getClass().getResource("/X509.png"))); // NOI18N
		jButtonDashX509.setText("Objets X509");
		jButtonDashX509.setHorizontalAlignment(javax.swing.SwingConstants.TRAILING);
		jButtonDashX509.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
		jButtonDashX509.setIconTextGap(10);
		jButtonDashX509.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDashX509ActionPerformed(evt);
			}
		});

		jButtonDashAbout.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
		jButtonDashAbout.setIcon(new javax.swing.ImageIcon(getClass().getResource("/about.png"))); // NOI18N
		jButtonDashAbout.setText("A propos");
		jButtonDashAbout.setHorizontalAlignment(javax.swing.SwingConstants.LEADING);
		jButtonDashAbout.setHorizontalTextPosition(javax.swing.SwingConstants.RIGHT);
		jButtonDashAbout.setIconTextGap(10);
		jButtonDashAbout.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDashAboutActionPerformed(evt);
			}
		});

		jLabel5.setBackground(new java.awt.Color(51, 51, 51));
		jLabel5.setIcon(new javax.swing.ImageIcon(getClass().getResource("/waves.gif"))); // NOI18N

		jLabel25.setIcon(null); // NOI18N

		javax.swing.GroupLayout jPanelDashboardLayout = new javax.swing.GroupLayout(jPanelDashboard);
		jPanelDashboardLayout.setHorizontalGroup(jPanelDashboardLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(jPanelDashboardLayout.createSequentialGroup().addGroup(jPanelDashboardLayout
						.createParallelGroup(Alignment.LEADING)
						.addGroup(jPanelDashboardLayout.createSequentialGroup().addGap(113)
								.addGroup(jPanelDashboardLayout.createParallelGroup(Alignment.LEADING)
										.addComponent(jButtonDashTransform, GroupLayout.PREFERRED_SIZE, 307,
												GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonDashX509, GroupLayout.PREFERRED_SIZE, 307,
												GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonDashGenerate, GroupLayout.PREFERRED_SIZE, 307,
												GroupLayout.PREFERRED_SIZE))
								.addGap(36).addComponent(jLabel5).addGap(30)
								.addGroup(jPanelDashboardLayout.createParallelGroup(Alignment.TRAILING)
										.addComponent(jButtonDashAnalyze, GroupLayout.PREFERRED_SIZE, 307,
												GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonDashAbout, GroupLayout.PREFERRED_SIZE, 307,
												GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonDashConvert, GroupLayout.PREFERRED_SIZE, 307,
												GroupLayout.PREFERRED_SIZE)))
						.addGroup(jPanelDashboardLayout.createSequentialGroup().addGap(541).addComponent(jLabel25)))
						.addContainerGap(127, Short.MAX_VALUE)));
		jPanelDashboardLayout.setVerticalGroup(jPanelDashboardLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(jPanelDashboardLayout.createSequentialGroup().addContainerGap()
						.addComponent(jLabel25, GroupLayout.DEFAULT_SIZE, 101, Short.MAX_VALUE).addGap(7)
						.addGroup(jPanelDashboardLayout.createParallelGroup(Alignment.LEADING, false)
								.addGroup(jPanelDashboardLayout.createSequentialGroup()
										.addComponent(jButtonDashGenerate).addGap(57).addComponent(jButtonDashTransform)
										.addPreferredGap(ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)
										.addComponent(jButtonDashX509))
								.addGroup(jPanelDashboardLayout.createSequentialGroup().addComponent(jButtonDashAnalyze)
										.addPreferredGap(ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)
										.addComponent(jButtonDashConvert).addGap(43).addComponent(jButtonDashAbout))
								.addComponent(jLabel5))
						.addGap(65)));
		jPanelDashboard.setLayout(jPanelDashboardLayout);

		jTabbedPaneScreens.addTab("Dashboard", jPanelDashboard);

		jPanel19.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Certificates",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		outline.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
		outline.getTableHeader().setResizingAllowed(false);
		jScrollPane1.setViewportView(outline);

		javax.swing.GroupLayout jPanel19Layout = new javax.swing.GroupLayout(jPanel19);
		jPanel19.setLayout(jPanel19Layout);
		jPanel19Layout.setHorizontalGroup(jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel19Layout.createSequentialGroup().addComponent(jScrollPane1).addContainerGap()));
		jPanel19Layout.setVerticalGroup(jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 348, Short.MAX_VALUE));

		jPanel20.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Keys",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jTablePK.setModel(
				new javax.swing.table.DefaultTableModel(new Object[][] { { null, null, null, null, null, null, null } },
						new String[] { "", "ID", "Key Name", "Type", "Algo", "SHA256", "Related to" }) {
					boolean[] canEdit = new boolean[] { false, false, false, false, false, false, false };

					public boolean isCellEditable(int rowIndex, int columnIndex) {
						return canEdit[columnIndex];
					}
				});
		jTablePK.getTableHeader().setReorderingAllowed(false);
		jScrollPane9.setViewportView(jTablePK);
		jTablePK.getColumnModel().getSelectionModel()
				.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_INTERVAL_SELECTION);
		if (jTablePK.getColumnModel().getColumnCount() > 0) {
			jTablePK.getColumnModel().getColumn(0).setResizable(false);
			jTablePK.getColumnModel().getColumn(0).setPreferredWidth(5);
		}

		javax.swing.GroupLayout jPanel20Layout = new javax.swing.GroupLayout(jPanel20);
		jPanel20.setLayout(jPanel20Layout);
		jPanel20Layout.setHorizontalGroup(
				jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addComponent(jScrollPane9,
						javax.swing.GroupLayout.PREFERRED_SIZE, 986, javax.swing.GroupLayout.PREFERRED_SIZE));
		jPanel20Layout.setVerticalGroup(jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jScrollPane9, javax.swing.GroupLayout.DEFAULT_SIZE, 272, Short.MAX_VALUE));

		jPanel21.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Associated CRLs",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jTableCRL.setModel(new javax.swing.table.DefaultTableModel(new Object[][] { { null, null, null } },
				new String[] { "ID", "Start Date", "End Date" }));
		jScrollPane2.setViewportView(jTableCRL);

		javax.swing.GroupLayout jPanel21Layout = new javax.swing.GroupLayout(jPanel21);
		jPanel21.setLayout(jPanel21Layout);
		jPanel21Layout.setHorizontalGroup(jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 416, Short.MAX_VALUE)
				.addGroup(jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel21Layout.createSequentialGroup()
								.addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 406, Short.MAX_VALUE)
								.addContainerGap())));
		jPanel21Layout.setVerticalGroup(jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE)
				.addGroup(jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 272, Short.MAX_VALUE)));

		javax.swing.GroupLayout jPanelACManagementLayout = new javax.swing.GroupLayout(jPanelACManagement);
		jPanelACManagement.setLayout(jPanelACManagementLayout);
		jPanelACManagementLayout.setHorizontalGroup(
				jPanelACManagementLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addComponent(jPanel19, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addGroup(jPanelACManagementLayout.createSequentialGroup()
								.addComponent(jPanel20, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jPanel21, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));
		jPanelACManagementLayout.setVerticalGroup(
				jPanelACManagementLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanelACManagementLayout.createSequentialGroup()
								.addComponent(jPanel19, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addGroup(jPanelACManagementLayout
										.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
										.addComponent(jPanel20, javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jPanel21, javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		jTabbedPaneScreens.addTab("  PKI  ", jPanelACManagement);

		jTabbedPaneGenerate.setMaximumSize(new java.awt.Dimension(1393, 662));

		jPanel2.setMaximumSize(new java.awt.Dimension(1388, 637));
		jPanel2.setMinimumSize(new java.awt.Dimension(1388, 637));
		jPanel2.setName(""); // NOI18N

		jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(),
				"PKCS#12 - Keystore", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
				javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jTextFieldKeystorePW.setToolTipText("");
		jTextFieldKeystorePW.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextFieldKeystorePWActionPerformed(evt);
			}
		});

		jLabel1.setText("Keystore Password : ");

		jLabel2.setText("CN :");

		jLabel3.setText("Private Key Password : ");

		jSpinnerKeySize.setValue(new Integer(2048));

		jLabel4.setText("Key Size : ");

		jComboBoxAC.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBoxACActionPerformed(evt);
			}
		});

		jLabel6.setText("Target Issuer : ");

		jLabel9.setText("Algorithm :");

		jComboBoxAlgoP12.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBoxAlgoP12ActionPerformed(evt);
			}
		});

		jLabel10.setText("Public Exponent :");
		jLabel10.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseEntered(java.awt.event.MouseEvent evt) {
				jLabel10MouseEntered(evt);
			}
		});

		jSpinnerP12Expo.setEnabled(false);
		jSpinnerP12Expo.setValue(new Integer(65537));

		jLabel11.setText("Certainty : ");

		jSliderP12Certainty.setToolTipText("");
		jSliderP12Certainty.setValue(5);
		jSliderP12Certainty.setEnabled(false);

		jCheckBoxP12Expo.setSelected(true);
		jCheckBoxP12Expo.setText("auto");
		jCheckBoxP12Expo.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxP12ExpoActionPerformed(evt);
			}
		});

		jCheckBoxP12Certainty.setSelected(true);
		jCheckBoxP12Certainty.setText("auto");
		jCheckBoxP12Certainty.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxP12CertaintyActionPerformed(evt);
			}
		});

		jButtonPKCS12Generate.setBackground(new Color(255, 165, 0));
		jButtonPKCS12Generate.setForeground(new Color(0, 0, 0));
		jButtonPKCS12Generate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/gears.png"))); // NOI18N
		jButtonPKCS12Generate.setText("Générer un keystore (PKCS#12)");
		jButtonPKCS12Generate.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.RAISED));
		jButtonPKCS12Generate.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonPKCS12GenerateActionPerformed(evt);
			}
		});

		jDateChooserP12Expiry.setName("JDateChooserExpiry"); // NOI18N

		jLabel31.setText("Expiry Date :");

		jLabel40.setText("Target Filename : ");

		jTextFieldP12TargetFilename.setText("keystore.p12");

		jCheckBoxP12Write.setText("Make crt and key file");
		jCheckBoxP12Write.setActionCommand("Write crt and key ?");

		javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
		jPanel1.setLayout(jPanel1Layout);
		jPanel1Layout.setHorizontalGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel1Layout.createSequentialGroup().addContainerGap().addGroup(jPanel1Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel1Layout.createSequentialGroup()
								.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addComponent(jLabel2).addComponent(jLabel1))
								.addGap(16, 16, 16))
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
								jPanel1Layout.createSequentialGroup().addComponent(jLabel3)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
						.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(jTextFieldCN).addComponent(jTextFieldKeystorePW)
								.addComponent(jTextFieldPKCS8PW, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(18, 18, 18)
						.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel4)
								.addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 77,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel40))
						.addGap(18, 18, 18)
						.addGroup(
								jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addGroup(jPanel1Layout.createSequentialGroup().addGroup(jPanel1Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
												.addComponent(jSpinnerKeySize, javax.swing.GroupLayout.DEFAULT_SIZE,
														150, Short.MAX_VALUE)
												.addComponent(jTextFieldP12TargetFilename)).addGap(14, 14, 14)
												.addComponent(jCheckBoxP12Write))
										.addComponent(jComboBoxAC, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(44, 44, 44)
						.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel9).addComponent(jLabel10).addComponent(jLabel11))
						.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel1Layout.createSequentialGroup().addGap(10, 10, 10)
										.addGroup(jPanel1Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
												.addComponent(jSpinnerP12Expo).addComponent(jComboBoxAlgoP12,
														javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)))
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
										jPanel1Layout.createSequentialGroup()
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
												.addComponent(jSliderP12Certainty,
														javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel1Layout.createSequentialGroup().addComponent(jCheckBoxP12Certainty)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jButtonPKCS12Generate, javax.swing.GroupLayout.PREFERRED_SIZE,
												220, javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel1Layout.createSequentialGroup().addComponent(jCheckBoxP12Expo)
										.addGap(10, 10, 10)
										.addComponent(jLabel31, javax.swing.GroupLayout.PREFERRED_SIZE, 77,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(18, 18, 18)
										.addComponent(jDateChooserP12Expiry, javax.swing.GroupLayout.PREFERRED_SIZE,
												150, javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(0, 124, Short.MAX_VALUE)))
						.addContainerGap()));
		jPanel1Layout.setVerticalGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel1Layout.createSequentialGroup().addContainerGap().addGroup(jPanel1Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel1Layout.createSequentialGroup().addGroup(jPanel1Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(jPanel1Layout
										.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jSpinnerKeySize, javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jLabel4).addComponent(jLabel9)
										.addComponent(jComboBoxAlgoP12, javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jLabel31))
								.addComponent(jDateChooserP12Expiry, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel10)
										.addComponent(jSpinnerP12Expo, javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jCheckBoxP12Expo)))
						.addGroup(jPanel1Layout.createSequentialGroup().addGroup(jPanel1Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING).addComponent(jLabel2)
								.addComponent(jTextFieldCN, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGap(5, 5, 5)
								.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel1)
										.addComponent(jTextFieldKeystorePW, javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jLabel40)
										.addComponent(jTextFieldP12TargetFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jCheckBoxP12Write))))
						.addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel1Layout.createSequentialGroup()
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addGroup(jPanel1Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jCheckBoxP12Certainty)
												.addGroup(jPanel1Layout.createSequentialGroup().addGap(3, 3, 3)
														.addGroup(jPanel1Layout
																.createParallelGroup(
																		javax.swing.GroupLayout.Alignment.BASELINE)
																.addComponent(jLabel11)
																.addComponent(jComboBoxAC,
																		javax.swing.GroupLayout.PREFERRED_SIZE, 20,
																		javax.swing.GroupLayout.PREFERRED_SIZE)
																.addComponent(jLabel6)
																.addComponent(jTextFieldPKCS8PW,
																		javax.swing.GroupLayout.PREFERRED_SIZE,
																		javax.swing.GroupLayout.DEFAULT_SIZE,
																		javax.swing.GroupLayout.PREFERRED_SIZE)
																.addComponent(jLabel3)))
												.addComponent(jSliderP12Certainty,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE))
										.addGap(39, 39, 39))
								.addGroup(jPanel1Layout.createSequentialGroup().addGap(18, 18, 18)
										.addComponent(jButtonPKCS12Generate)
										.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))));

		jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(),
				"PKCS#8 - Private Key", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
				javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jButtonPkGenerate.setBackground(new Color(255, 105, 180));
		jButtonPkGenerate.setForeground(new Color(0, 0, 0));
		jButtonPkGenerate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/gears.png"))); // NOI18N
		jButtonPkGenerate.setText("Générer une clef privée (PKCS#8)");
		jButtonPkGenerate.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.RAISED));
		jButtonPkGenerate.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonPkGenerateActionPerformed(evt);
			}
		});

		jLabel12.setText("Key Size : ");

		jSpinnerKeySizePkSize.setValue(new Integer(2048));

		jTextFieldPkTargetFilename.setText("private.key");

		jSliderPkCertainty.setToolTipText("");
		jSliderPkCertainty.setValue(5);
		jSliderPkCertainty.setEnabled(false);

		jLabel14.setText("Certainty : ");

		jCheckBoxPkCertainty.setSelected(true);
		jCheckBoxPkCertainty.setText("auto");
		jCheckBoxPkCertainty.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxPkCertaintyActionPerformed(evt);
			}
		});

		jLabel15.setText("Public Exponent :");
		jLabel15.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseEntered(java.awt.event.MouseEvent evt) {
				jLabel15MouseEntered(evt);
			}
		});

		jSpinnerPkExpo.setEnabled(false);
		jSpinnerPkExpo.setValue(new Integer(65537));

		jCheckBoxPkExpo.setSelected(true);
		jCheckBoxPkExpo.setText("auto");
		jCheckBoxPkExpo.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxPkExpoActionPerformed(evt);
			}
		});

		jComboBoxAlgoPk.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBoxAlgoPkActionPerformed(evt);
			}
		});

		jLabel16.setText("Algorithm :");

		jLabel17.setText("Private Key Password : ");

		jLabel27.setText("Target Filename : ");

		jLabel59.setText("Key Name :");

		jTextFieldPkTargetKeyName.setText("MyPrivateKey");

		javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
		jPanel3.setLayout(jPanel3Layout);
		jPanel3Layout.setHorizontalGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel3Layout.createSequentialGroup().addContainerGap().addGroup(jPanel3Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addGroup(jPanel3Layout.createSequentialGroup().addComponent(jLabel17)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addComponent(jTextFieldPkPw, javax.swing.GroupLayout.PREFERRED_SIZE, 147,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel3Layout.createSequentialGroup().addComponent(jLabel27)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jTextFieldPkTargetFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE, 147,
												javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addGroup(jPanel3Layout.createSequentialGroup().addComponent(jLabel16).addGap(66, 66, 66)
								.addComponent(jComboBoxAlgoPk, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addGap(137, 137, 137)
						.addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel15).addComponent(jLabel14).addComponent(jLabel12))
						.addGap(18, 18, 18)
						.addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel3Layout.createSequentialGroup().addGroup(jPanel3Layout
										.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addComponent(jSliderPkCertainty, javax.swing.GroupLayout.PREFERRED_SIZE, 135,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jSpinnerPkExpo, javax.swing.GroupLayout.PREFERRED_SIZE, 135,
												javax.swing.GroupLayout.PREFERRED_SIZE))
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addGroup(jPanel3Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addGroup(jPanel3Layout.createSequentialGroup()
														.addComponent(jCheckBoxPkExpo).addGap(0, 0, Short.MAX_VALUE))
												.addGroup(jPanel3Layout.createSequentialGroup()
														.addComponent(jCheckBoxPkCertainty)
														.addPreferredGap(
																javax.swing.LayoutStyle.ComponentPlacement.RELATED, 485,
																Short.MAX_VALUE)
														.addComponent(jButtonPkGenerate,
																javax.swing.GroupLayout.PREFERRED_SIZE, 220,
																javax.swing.GroupLayout.PREFERRED_SIZE))))
								.addGroup(jPanel3Layout.createSequentialGroup()
										.addComponent(jSpinnerKeySizePkSize, javax.swing.GroupLayout.PREFERRED_SIZE,
												150, javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(80, 80, 80)
										.addGroup(jPanel3Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addGroup(jPanel3Layout.createSequentialGroup().addGap(73, 73, 73)
														.addComponent(jTextFieldPkTargetKeyName,
																javax.swing.GroupLayout.PREFERRED_SIZE, 150,
																javax.swing.GroupLayout.PREFERRED_SIZE))
												.addComponent(jLabel59))
										.addGap(0, 0, Short.MAX_VALUE)))
						.addContainerGap()));
		jPanel3Layout
				.setVerticalGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addGroup(jPanel3Layout.createSequentialGroup().addGroup(jPanel3Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addGroup(jPanel3Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jLabel59).addComponent(jTextFieldPkTargetKeyName,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE))
												.addGroup(jPanel3Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jLabel12).addComponent(jSpinnerKeySizePkSize,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE)))
												.addGap(5, 5, 5)
												.addGroup(jPanel3Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jLabel15)
														.addComponent(jSpinnerPkExpo,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(jCheckBoxPkExpo))
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
												.addGroup(jPanel3Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
														.addComponent(jSliderPkCertainty,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(jLabel14,
																javax.swing.GroupLayout.Alignment.LEADING)
														.addGroup(javax.swing.GroupLayout.Alignment.LEADING,
																jPanel3Layout.createParallelGroup(
																		javax.swing.GroupLayout.Alignment.TRAILING)
																		.addComponent(jButtonPkGenerate)
																		.addComponent(jCheckBoxPkCertainty))))
										.addGroup(jPanel3Layout.createSequentialGroup()
												.addGroup(jPanel3Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jLabel27).addComponent(jTextFieldPkTargetFilename,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE))
												.addGap(4, 4, 4)
												.addGroup(jPanel3Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jComboBoxAlgoPk,
																javax.swing.GroupLayout.PREFERRED_SIZE, 20,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(jLabel16))
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
												.addGroup(jPanel3Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jLabel17).addComponent(jTextFieldPkPw,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE))))
								.addGap(52, 52, 52)));

		jPanel4.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(),
				"Certificate", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
				javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jButtonCertGenerate.setBackground(new java.awt.Color(50, 219, 35));
		jButtonCertGenerate.setForeground(new Color(0, 0, 0));
		jButtonCertGenerate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/gears.png"))); // NOI18N
		jButtonCertGenerate.setText("Générer un certificat");
		jButtonCertGenerate.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.RAISED));
		jButtonCertGenerate.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonCertGenerateActionPerformed(evt);
			}
		});

		jLabel19.setText("CN :");

		jLabel20.setText("Private Key Password : ");

		jLabel21.setText("Private Key File :");

		jLabel22.setText("Public Key File :");

		jButtonBrowseCertPub.setText("Import Key");
		jButtonBrowseCertPub.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseCertPubActionPerformed(evt);
			}
		});

		jButtonBrowseCertPk.setText("Import Key");
		jButtonBrowseCertPk.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseCertPkActionPerformed(evt);
			}
		});

		jLabel28.setText("Target Filename : ");

		jTextFieldCertTargetFilename.setText("enigma.crt");

		jDateChooserExpiry.setName("JDateChooserExpiry"); // NOI18N

		jLabel30.setText("Expiry Date :");

		jComboBoxCertAlgo.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBoxCertAlgoActionPerformed(evt);
			}
		});

		jLabel61.setText("Algorithm :");

		jLabel66.setText("Certificate Version :");

		jComboBoxCertVersion.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBoxCertVersionActionPerformed(evt);
			}
		});

		jLabel67.setText("Certificate Name :");

		jTextFieldPubTargetCertName.setText("Enigma");

		javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
		jPanel4.setLayout(jPanel4Layout);
		jPanel4Layout.setHorizontalGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel4Layout.createSequentialGroup().addContainerGap()
						.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel21).addComponent(jLabel22).addComponent(jLabel19))
						.addGap(37, 37, 37)
						.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(jTextFieldCertCN, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGroup(jPanel4Layout.createSequentialGroup()
										.addComponent(jComboBoxCertPubK, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addComponent(jButtonBrowseCertPub, javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
								.addGroup(jPanel4Layout.createSequentialGroup()
										.addComponent(jComboBoxCertPk, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addComponent(jButtonBrowseCertPk, javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
						.addGap(43, 43, 43)
						.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addGroup(jPanel4Layout.createSequentialGroup().addComponent(jLabel28)
										.addGap(37, 37, 37).addComponent(jTextFieldCertTargetFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel4Layout.createSequentialGroup().addComponent(jLabel20)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(jTextFieldCertPkPw, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel4Layout.createSequentialGroup().addComponent(jLabel67)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jTextFieldPubTargetCertName,
												javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addGap(38, 38, 38)
						.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addComponent(jLabel66, javax.swing.GroupLayout.Alignment.TRAILING)
										.addComponent(jLabel61))
								.addComponent(jLabel30, javax.swing.GroupLayout.PREFERRED_SIZE, 77,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jDateChooserExpiry, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jComboBoxCertAlgo, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jComboBoxCertVersion, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(jButtonCertGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 220,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addContainerGap()));
		jPanel4Layout.setVerticalGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel4Layout.createSequentialGroup().addContainerGap().addGroup(jPanel4Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel4Layout.createSequentialGroup().addGroup(jPanel4Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(jPanel4Layout
										.createSequentialGroup()
										.addGroup(jPanel4Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel19).addComponent(jTextFieldCertCN,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE))
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addGroup(jPanel4Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel21).addComponent(jButtonBrowseCertPk)
												.addComponent(jComboBoxCertPk, javax.swing.GroupLayout.PREFERRED_SIZE,
														20, javax.swing.GroupLayout.PREFERRED_SIZE))
										.addGap(13, 13, 13))
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout
										.createSequentialGroup()
										.addGroup(jPanel4Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel20).addComponent(jTextFieldCertPkPw,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE))
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addGroup(jPanel4Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jTextFieldPubTargetCertName,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jLabel67))
										.addGap(9, 9, 9)))
								.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel22).addComponent(jButtonBrowseCertPub)
										.addComponent(jComboBoxCertPubK, javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jLabel28).addComponent(jTextFieldCertTargetFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addGroup(jPanel4Layout.createSequentialGroup().addGap(6, 6, 6).addGroup(jPanel4Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel4Layout.createSequentialGroup().addComponent(jLabel30).addGap(6, 6, 6))
								.addComponent(jDateChooserExpiry, javax.swing.GroupLayout.Alignment.TRAILING,
										javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.PREFERRED_SIZE))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel61).addComponent(jComboBoxCertAlgo,
												javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGap(14, 14, 14)
								.addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel66)
										.addComponent(jComboBoxCertVersion, javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonCertGenerate))))
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		jPanel5.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(),
				"Public Key", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
				javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jButtonPubGenerate.setBackground(new java.awt.Color(102, 204, 255));
		jButtonPubGenerate.setForeground(new Color(0, 0, 0));
		jButtonPubGenerate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/gears.png"))); // NOI18N
		jButtonPubGenerate.setText("Générer une clef publique ");
		jButtonPubGenerate.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.RAISED));
		jButtonPubGenerate.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonPubGenerateActionPerformed(evt);
			}
		});

		jLabel23.setText("Private Key File :");

		jLabel24.setText("Private Key Password : ");

		jTextFieldPubPrivkeyPW.setMaximumSize(new java.awt.Dimension(6, 20));

		jLabel26.setText("Target Filename : ");

		jTextFieldPubTargetFilename.setText("public.key");

		jComboBoxPubPK.setMaximumSize(new java.awt.Dimension(29, 22));
		jComboBoxPubPK.setName(""); // NOI18N
		jComboBoxPubPK.setVerifyInputWhenFocusTarget(false);

		jLabel60.setText("Key Name :");

		jTextFieldPubTargetKeyName.setText("MyPublicKey");

		jButtonBrowsePubPk.setText("Import Key");
		jButtonBrowsePubPk.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowsePubPkActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
		jPanel5.setLayout(jPanel5Layout);
		jPanel5Layout.setHorizontalGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel5Layout.createSequentialGroup().addContainerGap()
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel23).addComponent(jLabel24))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addComponent(jTextFieldPubPrivkeyPW, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jComboBoxPubPK, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(jButtonBrowsePubPk).addGap(45, 45, 45)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel26).addComponent(jLabel60))
						.addGap(18, 18, 18)
						.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel5Layout.createSequentialGroup()
										.addComponent(jTextFieldPubTargetFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 514,
												Short.MAX_VALUE)
										.addComponent(jButtonPubGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 220,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel5Layout.createSequentialGroup()
										.addComponent(jTextFieldPubTargetKeyName,
												javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(0, 0, Short.MAX_VALUE)))
						.addContainerGap()));
		jPanel5Layout.setVerticalGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel5Layout.createSequentialGroup().addContainerGap().addGroup(jPanel5Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel5Layout.createSequentialGroup()
								.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jComboBoxPubPK, javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonBrowsePubPk))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addComponent(jTextFieldPubPrivkeyPW, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGroup(jPanel5Layout.createSequentialGroup().addGroup(jPanel5Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel60).addComponent(jTextFieldPubTargetKeyName,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addComponent(jLabel23))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel24).addComponent(jLabel26)
										.addComponent(jTextFieldPubTargetFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonPubGenerate))))
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		jPanel6.setBorder(javax.swing.BorderFactory.createTitledBorder(javax.swing.BorderFactory.createEtchedBorder(),
				"PKCS#10", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
				javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jButtonCSRGenerate.setBackground(new java.awt.Color(255, 153, 51));
		jButtonCSRGenerate.setForeground(new Color(0, 0, 0));
		jButtonCSRGenerate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/gears.png"))); // NOI18N
		jButtonCSRGenerate.setText("Générer un CSR (PKCS#10)");
		jButtonCSRGenerate.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.RAISED));
		jButtonCSRGenerate.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonCSRGenerateActionPerformed(evt);
			}
		});

		jLabel32.setText("Private Key File : ");

		jButtonBrowseP10Pk.setText("Import Key");
		jButtonBrowseP10Pk.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseP10PkActionPerformed(evt);
			}
		});

		jLabel34.setText("Private Key Password : ");

		jTextFieldP10PkPw.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextFieldP10PkPwActionPerformed(evt);
			}
		});

		jLabel36.setText("Requested CN :");

		jLabel37.setText("Target Filename : ");

		jTextFieldP10TargetFilename.setText("request.p10");

		jCheckBoxP10PubKey.setText("Use a specific Public Key ?");
		jCheckBoxP10PubKey.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxP10PubKeyActionPerformed(evt);
			}
		});

		jComboBoxCSRPubK.setEnabled(false);

		jButtonBrowseP10PubK.setText("Import Key");
		jButtonBrowseP10PubK.setEnabled(false);
		jButtonBrowseP10PubK.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseP10PubKActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
		jPanel6.setLayout(jPanel6Layout);
		jPanel6Layout.setHorizontalGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel6Layout.createSequentialGroup().addContainerGap()
						.addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel6Layout.createSequentialGroup()
										.addComponent(jLabel34, javax.swing.GroupLayout.PREFERRED_SIZE, 114,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(
												jTextFieldP10PkPw, javax.swing.GroupLayout.PREFERRED_SIZE, 146,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel6Layout.createSequentialGroup()
										.addGroup(jPanel6Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addComponent(jLabel36).addComponent(jLabel32))
										.addGroup(jPanel6Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
												.addGroup(jPanel6Layout.createSequentialGroup().addGap(40, 40, 40)
														.addComponent(jTextFieldP10CN,
																javax.swing.GroupLayout.PREFERRED_SIZE, 146,
																javax.swing.GroupLayout.PREFERRED_SIZE))
												.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
														jPanel6Layout.createSequentialGroup().addPreferredGap(
																javax.swing.LayoutStyle.ComponentPlacement.RELATED)
																.addComponent(jComboBoxCSRPk,
																		javax.swing.GroupLayout.PREFERRED_SIZE, 146,
																		javax.swing.GroupLayout.PREFERRED_SIZE)))
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addComponent(jButtonBrowseP10Pk)))
						.addGap(45, 45, 45)
						.addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel6Layout.createSequentialGroup().addComponent(jLabel37)
										.addGap(54, 54, 54)
										.addComponent(jTextFieldP10TargetFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jButtonCSRGenerate, javax.swing.GroupLayout.PREFERRED_SIZE, 220,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel6Layout.createSequentialGroup().addComponent(jCheckBoxP10PubKey)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(jComboBoxCSRPubK, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addComponent(jButtonBrowseP10PubK).addGap(0, 0, Short.MAX_VALUE)))
						.addContainerGap()));
		jPanel6Layout.setVerticalGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel6Layout.createSequentialGroup()
						.addContainerGap()
						.addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel36).addComponent(jTextFieldP10CN,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
										jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jTextFieldP10TargetFilename,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jLabel37)))
						.addGap(18, 18, 18)
						.addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jCheckBoxP10PubKey)
										.addComponent(jComboBoxCSRPubK, javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonBrowseP10PubK))
								.addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel32)
										.addComponent(jComboBoxCSRPk, javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonBrowseP10Pk)))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jTextFieldP10PkPw, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jLabel34))
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel6Layout.createSequentialGroup()
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jButtonCSRGenerate).addContainerGap()));

		javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
		jPanel2.setLayout(jPanel2Layout);
		jPanel2Layout.setHorizontalGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel4, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE,
						javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
				.addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel3, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE,
						javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));
		jPanel2Layout.setVerticalGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel2Layout.createSequentialGroup()
						.addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, 127,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, 119,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(1, 1, 1).addComponent(jPanel6, javax.swing.GroupLayout.DEFAULT_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		jTabbedPaneGenerate.addTab("X509", jPanel2);

		jLabel57.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
		jLabel57.setText("Coming soon ... ");

		javax.swing.GroupLayout jPanel14Layout = new javax.swing.GroupLayout(jPanel14);
		jPanel14.setLayout(jPanel14Layout);
		jPanel14Layout.setHorizontalGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel14Layout.createSequentialGroup().addGap(586, 586, 586).addComponent(jLabel57)
						.addContainerGap(697, Short.MAX_VALUE)));
		jPanel14Layout.setVerticalGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel14Layout.createSequentialGroup().addGap(293, 293, 293).addComponent(jLabel57)
						.addContainerGap(322, Short.MAX_VALUE)));

		jTabbedPaneGenerate.addTab("PGP", jPanel14);

		jTabbedPaneScreens.addTab("Générer", jTabbedPaneGenerate);

		jPanel11.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Signer",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N
		jPanel11.setMaximumSize(new java.awt.Dimension(1427, 149));
		jPanel11.setMinimumSize(new java.awt.Dimension(1427, 149));
		jPanel11.setName(""); // NOI18N

		jLabel41.setText("Target File :");

		jLabel42.setText("Private Key for sign :");

		jTextFieldSignFile.addInputMethodListener(new java.awt.event.InputMethodListener() {
			public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
			}

			public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
				jTextFieldSignFileInputMethodTextChanged(evt);
			}
		});
		jTextFieldSignFile.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextFieldSignFileActionPerformed(evt);
			}
		});

		jButtonBrowseSignFile.setText("Parcourir...");
		jButtonBrowseSignFile.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseSignFileActionPerformed(evt);
			}
		});

		jLabel43.setText("Algorithm :");

		jComboBoxAlgoSign.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBoxAlgoSignActionPerformed(evt);
			}
		});

		jButtonSign.setBackground(new java.awt.Color(107, 94, 242));
		jButtonSign.setForeground(new Color(0, 0, 0));
		jButtonSign.setIcon(new javax.swing.ImageIcon(getClass().getResource("/sign.png"))); // NOI18N
		jButtonSign.setText("Sign File");
		jButtonSign.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonSignActionPerformed(evt);
			}
		});

		jLabel46.setText("Private Key Password :");

		jCheckBox2.setText("Use custom name");
		jCheckBox2.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBox2ActionPerformed(evt);
			}
		});

		jLabel52.setText("Signer certificate :");

		jLabel44.setText("Output Filename : ");

		jTextFieldSignOutputFilename.setEnabled(false);
		jTextFieldSignOutputFilename.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextFieldSignOutputFilenameActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanel11Layout = new javax.swing.GroupLayout(jPanel11);
		jPanel11.setLayout(jPanel11Layout);
		jPanel11Layout.setHorizontalGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel11Layout.createSequentialGroup().addContainerGap().addGroup(jPanel11Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
						.addGroup(jPanel11Layout.createSequentialGroup().addComponent(jLabel41).addGap(78, 78, 78)
								.addComponent(jTextFieldSignFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGap(8, 8, 8).addComponent(jButtonBrowseSignFile,
										javax.swing.GroupLayout.PREFERRED_SIZE, 95,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGroup(jPanel11Layout.createSequentialGroup()
								.addComponent(jLabel52, javax.swing.GroupLayout.PREFERRED_SIZE, 126,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addComponent(jComboBoxSignSignerCert, 0, javax.swing.GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE))
						.addGroup(jPanel11Layout.createSequentialGroup()
								.addComponent(jLabel42, javax.swing.GroupLayout.PREFERRED_SIZE, 126,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED).addComponent(
										jComboBoxSignPK, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 105, Short.MAX_VALUE)
						.addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel43).addComponent(jLabel46).addComponent(jLabel44))
						.addGap(18, 18, 18)
						.addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel11Layout.createSequentialGroup()
										.addComponent(jTextFieldSignOutputFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(2, 2, 2).addComponent(jCheckBox2))
								.addComponent(jTextFieldSignPkPassword, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jComboBoxAlgoSign, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGap(291, 291, 291).addComponent(jButtonSign, javax.swing.GroupLayout.PREFERRED_SIZE, 220,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addContainerGap()));
		jPanel11Layout.setVerticalGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel11Layout.createSequentialGroup().addContainerGap().addGroup(jPanel11Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
						.addGroup(jPanel11Layout.createSequentialGroup().addGroup(jPanel11Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE).addComponent(jLabel41)
								.addComponent(jTextFieldSignFile, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jButtonBrowseSignFile)).addGap(18, 18, 18)
								.addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel42).addComponent(jComboBoxSignPK,
												javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGap(18, 18, 18)
								.addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addGroup(jPanel11Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel52).addComponent(jComboBoxSignSignerCert,
														javax.swing.GroupLayout.PREFERRED_SIZE, 20,
														javax.swing.GroupLayout.PREFERRED_SIZE))
										.addComponent(jButtonSign)))
						.addGroup(jPanel11Layout.createSequentialGroup()
								.addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addGroup(jPanel11Layout.createSequentialGroup().addGap(40, 40, 40)
												.addGroup(jPanel11Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jLabel46).addComponent(jTextFieldSignPkPassword,
																javax.swing.GroupLayout.PREFERRED_SIZE,
																javax.swing.GroupLayout.DEFAULT_SIZE,
																javax.swing.GroupLayout.PREFERRED_SIZE)))
										.addGroup(jPanel11Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel43)
												.addComponent(jComboBoxAlgoSign, javax.swing.GroupLayout.PREFERRED_SIZE,
														20, javax.swing.GroupLayout.PREFERRED_SIZE)))
								.addGap(18, 18, 18)
								.addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jTextFieldSignOutputFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jCheckBox2).addComponent(jLabel44))
								.addGap(4, 4, 4)))
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		jPanel13.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Chiffrer",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jLabel47.setText("Target File :");

		jTextFieldCipherFile.addInputMethodListener(new java.awt.event.InputMethodListener() {
			public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
			}

			public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
				jTextFieldCipherFileInputMethodTextChanged(evt);
			}
		});
		jTextFieldCipherFile.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextFieldCipherFileActionPerformed(evt);
			}
		});

		jButtonBrowseCipherFile.setText("Parcourir...");
		jButtonBrowseCipherFile.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseCipherFileActionPerformed(evt);
			}
		});

		jButtonCipher.setBackground(new java.awt.Color(0, 153, 255));
		jButtonCipher.setForeground(new Color(0, 0, 0));
		jButtonCipher.setIcon(new javax.swing.ImageIcon(getClass().getResource("/lock.gif"))); // NOI18N
		jButtonCipher.setText("Encrypt File");
		jButtonCipher.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonCipherActionPerformed(evt);
			}
		});

		jComboBoxAlgoCipher.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jComboBoxAlgoCipherActionPerformed(evt);
			}
		});

		jLabel51.setText("Algorithm :");

		jLabel69.setText("Output Filename : ");

		jTextFieldCipherOutputFilename.setEnabled(false);

		jCheckBoxCustomCipher.setText("Use custom name");
		jCheckBoxCustomCipher.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxCustomCipherActionPerformed(evt);
			}
		});

		jLabel70.setText("Certificate for encrypt :");

		javax.swing.GroupLayout jPanel13Layout = new javax.swing.GroupLayout(jPanel13);
		jPanel13.setLayout(jPanel13Layout);
		jPanel13Layout.setHorizontalGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel13Layout.createSequentialGroup().addContainerGap().addGroup(jPanel13Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
						.addGroup(jPanel13Layout.createSequentialGroup().addComponent(jLabel47).addGap(78, 78, 78)
								.addComponent(jTextFieldCipherFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGap(8, 8, 8).addComponent(jButtonBrowseCipherFile,
										javax.swing.GroupLayout.PREFERRED_SIZE, 95,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGroup(jPanel13Layout.createSequentialGroup()
								.addComponent(jLabel70, javax.swing.GroupLayout.PREFERRED_SIZE, 126,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addComponent(jComboBoxCipherCert, javax.swing.GroupLayout.PREFERRED_SIZE, 253,
										javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addGap(102, 102, 102)
						.addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel51).addComponent(jLabel69))
						.addGap(43, 43, 43)
						.addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jComboBoxAlgoCipher, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGroup(jPanel13Layout.createSequentialGroup()
										.addComponent(jTextFieldCipherOutputFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(2, 2, 2).addComponent(jCheckBoxCustomCipher)))
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
				.addGroup(
						jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(
										jPanel13Layout.createSequentialGroup().addContainerGap(1185, Short.MAX_VALUE)
												.addComponent(jButtonCipher, javax.swing.GroupLayout.PREFERRED_SIZE,
														220, javax.swing.GroupLayout.PREFERRED_SIZE)
												.addContainerGap())));
		jPanel13Layout.setVerticalGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel13Layout.createSequentialGroup().addGap(23, 23, 23).addGroup(jPanel13Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel13Layout.createSequentialGroup()
								.addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel51).addComponent(jComboBoxAlgoCipher,
												javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGap(18, 18, 18)
								.addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jTextFieldCipherOutputFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jCheckBoxCustomCipher).addComponent(jLabel69)))
						.addGroup(jPanel13Layout.createSequentialGroup().addGroup(jPanel13Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE).addComponent(jLabel47)
								.addComponent(jTextFieldCipherFile, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jButtonBrowseCipherFile)).addGap(18, 18, 18)
								.addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel70).addComponent(jComboBoxCipherCert,
												javax.swing.GroupLayout.PREFERRED_SIZE, 20,
												javax.swing.GroupLayout.PREFERRED_SIZE))))
						.addContainerGap(39, Short.MAX_VALUE))
				.addGroup(jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel13Layout.createSequentialGroup().addGap(87, 87, 87).addComponent(jButtonCipher)
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))));

		jPanel15.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Déchiffrer",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jLabel45.setText("Target File :");

		jTextFieldSignFile1.addInputMethodListener(new java.awt.event.InputMethodListener() {
			public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
			}

			public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
				jTextFieldSignFile1InputMethodTextChanged(evt);
			}
		});
		jTextFieldSignFile1.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextFieldSignFile1ActionPerformed(evt);
			}
		});

		jButtonBrowseSignFile1.setText("Parcourir...");
		jButtonBrowseSignFile1.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseSignFile1ActionPerformed(evt);
			}
		});

		jLabel73.setText("Private Key for decrypt :");

		jLabel74.setText("Private Key Password :");

		jLabel75.setText("Output Filename : ");

		jTextFieldDecryptOutputFilename.setEnabled(false);
		jTextFieldDecryptOutputFilename.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextFieldDecryptOutputFilenameActionPerformed(evt);
			}
		});

		jCheckBoxCustomDecrypt.setText("Use custom name");
		jCheckBoxCustomDecrypt.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxCustomDecryptActionPerformed(evt);
			}
		});

		jButtonDecrypt.setBackground(new java.awt.Color(153, 51, 0));
		jButtonDecrypt.setForeground(new Color(0, 0, 0));
		jButtonDecrypt.setIcon(new javax.swing.ImageIcon(getClass().getResource("/keypub.png"))); // NOI18N
		jButtonDecrypt.setText("Decrypt File");
		jButtonDecrypt.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDecryptActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanel15Layout = new javax.swing.GroupLayout(jPanel15);
		jPanel15.setLayout(jPanel15Layout);
		jPanel15Layout.setHorizontalGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel15Layout.createSequentialGroup().addContainerGap().addGroup(jPanel15Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
						.addGroup(jPanel15Layout.createSequentialGroup().addComponent(jLabel45).addGap(78, 78, 78)
								.addComponent(jTextFieldSignFile1, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGap(8, 8, 8).addComponent(jButtonBrowseSignFile1,
										javax.swing.GroupLayout.PREFERRED_SIZE, 95,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addGroup(jPanel15Layout.createSequentialGroup()
								.addComponent(jLabel73, javax.swing.GroupLayout.PREFERRED_SIZE, 126,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
								.addComponent(jComboBoxCipher, javax.swing.GroupLayout.PREFERRED_SIZE, 253,
										javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel74).addComponent(jLabel75))
						.addGap(18, 18, 18)
						.addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jTextFieldSignPkPassword1, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addGroup(jPanel15Layout.createSequentialGroup()
										.addComponent(jTextFieldDecryptOutputFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addComponent(jCheckBoxCustomDecrypt)))
						.addGap(521, 521, 521))
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel15Layout.createSequentialGroup()
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addComponent(jButtonDecrypt, javax.swing.GroupLayout.PREFERRED_SIZE, 220,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addContainerGap()));
		jPanel15Layout.setVerticalGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel15Layout.createSequentialGroup()
						.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addGroup(jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
								.addGroup(jPanel15Layout.createSequentialGroup().addGroup(jPanel15Layout
										.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel45)
										.addComponent(jTextFieldSignFile1, javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jButtonBrowseSignFile1).addComponent(jLabel75)).addGap(18, 18, 18)
										.addGroup(jPanel15Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel73).addComponent(jComboBoxCipher,
														javax.swing.GroupLayout.PREFERRED_SIZE, 20,
														javax.swing.GroupLayout.PREFERRED_SIZE))
										.addGap(63, 63, 63))
								.addGroup(jPanel15Layout.createSequentialGroup()
										.addGroup(jPanel15Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jTextFieldDecryptOutputFilename,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addComponent(jCheckBoxCustomDecrypt))
										.addGap(18, 18, 18)
										.addGroup(jPanel15Layout
												.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
												.addComponent(jLabel74).addComponent(jTextFieldSignPkPassword1,
														javax.swing.GroupLayout.PREFERRED_SIZE,
														javax.swing.GroupLayout.DEFAULT_SIZE,
														javax.swing.GroupLayout.PREFERRED_SIZE))
										.addGap(29, 29, 29).addComponent(jButtonDecrypt).addContainerGap()))));

		jPanel16.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Vérifier signature",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jCheckBoxCustomVerify.setText("Use custom name");
		jCheckBoxCustomVerify.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxCustomVerifyActionPerformed(evt);
			}
		});

		jTextFieldVerifyOutputFilename.setEnabled(false);

		jLabel71.setText("Output Filename : ");

		jLabel72.setText("Validation certificate :");

		jLabel68.setText("Target File :");

		jTextFieldVerifyFile.addInputMethodListener(new java.awt.event.InputMethodListener() {
			public void caretPositionChanged(java.awt.event.InputMethodEvent evt) {
			}

			public void inputMethodTextChanged(java.awt.event.InputMethodEvent evt) {
				jTextFieldVerifyFileInputMethodTextChanged(evt);
			}
		});
		jTextFieldVerifyFile.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jTextFieldVerifyFileActionPerformed(evt);
			}
		});

		jButtonBrowseVerifyFile.setText("Parcourir...");
		jButtonBrowseVerifyFile.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseVerifyFileActionPerformed(evt);
			}
		});

		jButtonValidate.setBackground(new java.awt.Color(102, 0, 102));
		jButtonValidate.setForeground(new Color(0, 0, 0));
		jButtonValidate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/bluval.png"))); // NOI18N
		jButtonValidate.setText("Validate Signature");
		jButtonValidate.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonValidateActionPerformed(evt);
			}
		});

		jCheckBoxCustomVerifyTryAll.setText("Try everything !");
		jCheckBoxCustomVerifyTryAll.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jCheckBoxCustomVerifyTryAllActionPerformed(evt);
			}
		});

		jButtonVerify.setBackground(new java.awt.Color(0, 153, 0));
		jButtonVerify.setForeground(new Color(0, 0, 0));
		jButtonVerify.setIcon(new javax.swing.ImageIcon(getClass().getResource("/validd.png"))); // NOI18N
		jButtonVerify.setText("Verify Signature");
		jButtonVerify.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonVerifyActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanel16Layout = new javax.swing.GroupLayout(jPanel16);
		jPanel16.setLayout(jPanel16Layout);
		jPanel16Layout.setHorizontalGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel16Layout.createSequentialGroup().addContainerGap().addGroup(jPanel16Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel16Layout.createSequentialGroup().addGroup(jPanel16Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
								.addGroup(jPanel16Layout.createSequentialGroup().addComponent(jLabel68)
										.addGap(78, 78, 78)
										.addComponent(jTextFieldVerifyFile, javax.swing.GroupLayout.PREFERRED_SIZE, 150,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(8, 8, 8).addComponent(jButtonBrowseVerifyFile,
												javax.swing.GroupLayout.PREFERRED_SIZE, 95,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGroup(jPanel16Layout.createSequentialGroup()
										.addComponent(jLabel72, javax.swing.GroupLayout.PREFERRED_SIZE, 126,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(jComboBoxVerifyCert, javax.swing.GroupLayout.PREFERRED_SIZE, 253,
												javax.swing.GroupLayout.PREFERRED_SIZE)))
								.addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addGroup(jPanel16Layout.createSequentialGroup()
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
												.addComponent(jCheckBoxCustomVerifyTryAll)
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
														javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
												.addComponent(jButtonVerify, javax.swing.GroupLayout.PREFERRED_SIZE,
														220, javax.swing.GroupLayout.PREFERRED_SIZE))
										.addGroup(jPanel16Layout.createSequentialGroup().addGap(101, 101, 101)
												.addComponent(jLabel71).addGap(44, 44, 44)
												.addComponent(jTextFieldVerifyOutputFilename,
														javax.swing.GroupLayout.PREFERRED_SIZE, 150,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
												.addComponent(jCheckBoxCustomVerify).addGap(0, 0, Short.MAX_VALUE))))
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
								jPanel16Layout.createSequentialGroup().addGap(0, 0, Short.MAX_VALUE).addComponent(
										jButtonValidate, javax.swing.GroupLayout.PREFERRED_SIZE, 220,
										javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addContainerGap()));
		jPanel16Layout.setVerticalGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel16Layout.createSequentialGroup().addGroup(jPanel16Layout
						.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel16Layout.createSequentialGroup().addGap(38, 38, 38).addGroup(jPanel16Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE).addComponent(jLabel68)
								.addComponent(jTextFieldVerifyFile, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jButtonBrowseVerifyFile)))
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel16Layout.createSequentialGroup()
								.addContainerGap()
								.addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jLabel71)
										.addComponent(jTextFieldVerifyOutputFilename,
												javax.swing.GroupLayout.PREFERRED_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jCheckBoxCustomVerify))))
						.addGap(18, 18, 18)
						.addGroup(jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
								.addComponent(jLabel72)
								.addComponent(jComboBoxVerifyCert, javax.swing.GroupLayout.PREFERRED_SIZE, 20,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jCheckBoxCustomVerifyTryAll).addComponent(jButtonVerify))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(jButtonValidate).addContainerGap()));

		javax.swing.GroupLayout jPanel9Layout = new javax.swing.GroupLayout(jPanel9);
		jPanel9.setLayout(jPanel9Layout);
		jPanel9Layout.setHorizontalGroup(jPanel9Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel15, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel16, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel13, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addComponent(jPanel11, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						javax.swing.GroupLayout.PREFERRED_SIZE));
		jPanel9Layout.setVerticalGroup(jPanel9Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel9Layout.createSequentialGroup()
						.addComponent(jPanel11, javax.swing.GroupLayout.PREFERRED_SIZE, 144,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(1, 1, 1)
						.addComponent(jPanel13, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(jPanel16, javax.swing.GroupLayout.PREFERRED_SIZE, 166,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED).addComponent(jPanel15,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
								Short.MAX_VALUE)));

		jTabbedPane1.addTab("X509", jPanel9);

		javax.swing.GroupLayout jPanel10Layout = new javax.swing.GroupLayout(jPanel10);
		jPanel10.setLayout(jPanel10Layout);
		jPanel10Layout.setHorizontalGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));
		jPanel10Layout.setVerticalGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGap(0, 0, Short.MAX_VALUE));

		jTabbedPane1.addTab("PGP", jPanel10);

		javax.swing.GroupLayout jPanelTransformLayout = new javax.swing.GroupLayout(jPanelTransform);
		jPanelTransform.setLayout(jPanelTransformLayout);
		jPanelTransformLayout.setHorizontalGroup(jPanelTransformLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 1432, Short.MAX_VALUE)
				.addGroup(jPanelTransformLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addComponent(jTabbedPane1)));
		jPanelTransformLayout.setVerticalGroup(jPanelTransformLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGap(0, 662, Short.MAX_VALUE)
				.addGroup(jPanelTransformLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addComponent(jTabbedPane1)));

		jTabbedPaneScreens.addTab("Transformer", jPanelTransform);

		jLabel7.setText("Target file : ");

		jButton7.setText("Browse...");
		jButton7.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton7ActionPerformed(evt);
			}
		});

		jEditorPaneIdentifierResults.setEditable(false);
		jEditorPaneIdentifierResults.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
		jScrollPane3.setViewportView(jEditorPaneIdentifierResults);

		jLabel8.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
		jLabel8.setText("Results :");

		jPanel12.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Drag & Drop Zone : ",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N
		jPanel12.setName(""); // NOI18N

		jTextAreaDrop.setBackground(javax.swing.UIManager.getDefaults().getColor("Panel.background"));
		jTextAreaDrop.setColumns(20);
		jTextAreaDrop.setRows(5);
		jTextAreaDrop.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
		jTextAreaDrop.setFocusable(false);
		jScrollPane4.setViewportView(jTextAreaDrop);

		javax.swing.GroupLayout jPanel12Layout = new javax.swing.GroupLayout(jPanel12);
		jPanel12.setLayout(jPanel12Layout);
		jPanel12Layout.setHorizontalGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 488, Short.MAX_VALUE));
		jPanel12Layout.setVerticalGroup(jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 129, Short.MAX_VALUE));

		jButton8.setBackground(new java.awt.Color(107, 184, 11));
		jButton8.setForeground(new Color(0, 0, 0));
		jButton8.setText("Start Analysis");
		jButton8.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButton8ActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanelAnalyzeLayout = new javax.swing.GroupLayout(jPanelAnalyze);
		jPanelAnalyzeLayout.setHorizontalGroup(jPanelAnalyzeLayout.createParallelGroup(Alignment.LEADING)
				.addComponent(jScrollPane3, GroupLayout.DEFAULT_SIZE, 1432, Short.MAX_VALUE)
				.addGroup(jPanelAnalyzeLayout.createSequentialGroup().addGroup(jPanelAnalyzeLayout
						.createParallelGroup(Alignment.LEADING)
						.addGroup(jPanelAnalyzeLayout.createSequentialGroup().addContainerGap().addComponent(jLabel8))
						.addGroup(jPanelAnalyzeLayout.createSequentialGroup().addGap(427)
								.addGroup(jPanelAnalyzeLayout.createParallelGroup(Alignment.LEADING, false)
										.addGroup(jPanelAnalyzeLayout.createSequentialGroup().addGap(8)
												.addComponent(jLabel7).addGap(18)
												.addComponent(jTextFieldDrop, GroupLayout.PREFERRED_SIZE, 322,
														GroupLayout.PREFERRED_SIZE)
												.addPreferredGap(ComponentPlacement.RELATED).addComponent(jButton7))
										.addComponent(jPanel12, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
												GroupLayout.PREFERRED_SIZE))))
						.addContainerGap(505, Short.MAX_VALUE))
				.addGroup(jPanelAnalyzeLayout.createSequentialGroup().addGap(586)
						.addComponent(jButton8, GroupLayout.PREFERRED_SIZE, 188, GroupLayout.PREFERRED_SIZE)
						.addContainerGap(658, Short.MAX_VALUE)));
		jPanelAnalyzeLayout.setVerticalGroup(jPanelAnalyzeLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(jPanelAnalyzeLayout.createSequentialGroup().addGap(31)
						.addGroup(jPanelAnalyzeLayout.createParallelGroup(Alignment.BASELINE).addComponent(jLabel7)
								.addComponent(jTextFieldDrop, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
										GroupLayout.PREFERRED_SIZE)
								.addComponent(jButton7))
						.addPreferredGap(ComponentPlacement.RELATED)
						.addComponent(jPanel12, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE,
								GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(ComponentPlacement.RELATED).addComponent(jButton8).addGap(18)
						.addComponent(jLabel8).addPreferredGap(ComponentPlacement.RELATED)
						.addComponent(jScrollPane3, GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE)));
		jPanelAnalyze.setLayout(jPanelAnalyzeLayout);

		jTabbedPaneScreens.addTab("Analyser", jPanelAnalyze);

		jPanel18.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Base64 Encode/Decode",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N
		jPanel18.setFont(new java.awt.Font("Segoe UI Semibold", 0, 12)); // NOI18N

		jTextAreaOriginalData.setColumns(20);
		jTextAreaOriginalData.setRows(5);
		jScrollPane5.setViewportView(jTextAreaOriginalData);

		jTextAreaBase64Data.setColumns(20);
		jTextAreaBase64Data.setRows(5);
		jScrollPane8.setViewportView(jTextAreaBase64Data);

		jLabel54.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
		jLabel54.setText("Base64 Data :");

		jLabel55.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
		jLabel55.setText("ASCII Data :");

		jButtonEncodeBase64.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
		jButtonEncodeBase64.setText("< ENCODE BASE64 <");
		jButtonEncodeBase64.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonEncodeBase64ActionPerformed(evt);
			}
		});

		jButtonDecodeBase64.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
		jButtonDecodeBase64.setText("> DECODE BASE64 >");
		jButtonDecodeBase64.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonDecodeBase64ActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanel18Layout = new javax.swing.GroupLayout(jPanel18);
		jPanel18.setLayout(jPanel18Layout);
		jPanel18Layout
				.setHorizontalGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel18Layout.createSequentialGroup()
								.addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addGroup(jPanel18Layout.createSequentialGroup().addGap(23, 23, 23)
												.addComponent(jLabel54)
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
														javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
										.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel18Layout
												.createSequentialGroup().addContainerGap(596, Short.MAX_VALUE)
												.addGroup(jPanel18Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
														.addComponent(jButtonDecodeBase64,
																javax.swing.GroupLayout.PREFERRED_SIZE, 223,
																javax.swing.GroupLayout.PREFERRED_SIZE)
														.addComponent(jButtonEncodeBase64,
																javax.swing.GroupLayout.PREFERRED_SIZE, 223,
																javax.swing.GroupLayout.PREFERRED_SIZE))
												.addGap(18, 18, 18)))
								.addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
										.addComponent(jLabel55).addComponent(jScrollPane5,
												javax.swing.GroupLayout.PREFERRED_SIZE, 561,
												javax.swing.GroupLayout.PREFERRED_SIZE))
								.addGap(22, 22, 22))
						.addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel18Layout.createSequentialGroup().addGap(20, 20, 20)
										.addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, 553,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addContainerGap(837, Short.MAX_VALUE))));
		jPanel18Layout.setVerticalGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel18Layout.createSequentialGroup().addContainerGap(14, Short.MAX_VALUE)
						.addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
										jPanel18Layout.createSequentialGroup()
												.addGroup(jPanel18Layout
														.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
														.addComponent(jLabel54).addComponent(jLabel55))
												.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
												.addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 299,
														javax.swing.GroupLayout.PREFERRED_SIZE)
												.addContainerGap())
								.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel18Layout
										.createSequentialGroup()
										.addComponent(jButtonDecodeBase64, javax.swing.GroupLayout.PREFERRED_SIZE, 79,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(55, 55, 55)
										.addComponent(jButtonEncodeBase64, javax.swing.GroupLayout.PREFERRED_SIZE, 73,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(56, 56, 56))))
				.addGroup(jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
						javax.swing.GroupLayout.Alignment.TRAILING,
						jPanel18Layout.createSequentialGroup().addContainerGap(40, Short.MAX_VALUE)
								.addComponent(jScrollPane8, javax.swing.GroupLayout.PREFERRED_SIZE, 298,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addContainerGap())));

		jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Convert PEM/DER",
				javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION,
				new java.awt.Font("Tahoma", 1, 11))); // NOI18N

		jRadioButtonDER.setText("DER");
		jRadioButtonDER.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jRadioButtonDERActionPerformed(evt);
			}
		});

		jLabel33.setText("Source file :");

		jButtonConvertSourceFile.setText("Parcourir...");
		jButtonConvertSourceFile.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonConvertSourceFileActionPerformed(evt);
			}
		});

		jRadioButtonPEM.setSelected(true);
		jRadioButtonPEM.setText("PEM");
		jRadioButtonPEM.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jRadioButtonPEMActionPerformed(evt);
			}
		});

		jRadioButtonPEMorDER.setText("I don't know");
		jRadioButtonPEMorDER.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jRadioButtonPEMorDERActionPerformed(evt);
			}
		});

		jButtonConvertPEM.setBackground(new java.awt.Color(204, 255, 204));
		jButtonConvertPEM.setText("Convert to PEM");
		jButtonConvertPEM.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonConvertPEMActionPerformed(evt);
			}
		});

		jButtonConvertDER.setBackground(new java.awt.Color(255, 204, 204));
		jButtonConvertDER.setText("Convert to DER");
		jButtonConvertDER.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonConvertDERActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
		jPanel7.setLayout(jPanel7Layout);
		jPanel7Layout.setHorizontalGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel7Layout.createSequentialGroup().addGap(29, 29, 29)
						.addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jLabel33).addComponent(jRadioButtonPEM,
										javax.swing.GroupLayout.PREFERRED_SIZE, 55,
										javax.swing.GroupLayout.PREFERRED_SIZE))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
						.addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addGroup(jPanel7Layout.createSequentialGroup()
										.addComponent(jRadioButtonDER, javax.swing.GroupLayout.PREFERRED_SIZE, 55,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
										.addComponent(jRadioButtonPEMorDER))
								.addGroup(jPanel7Layout.createSequentialGroup()
										.addComponent(jTextFieldConvertSourceFile,
												javax.swing.GroupLayout.PREFERRED_SIZE, 363,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addComponent(jButtonConvertSourceFile, javax.swing.GroupLayout.PREFERRED_SIZE,
												95, javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED,
								javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addComponent(jButtonConvertPEM, javax.swing.GroupLayout.PREFERRED_SIZE, 183,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(69, 69, 69).addComponent(jButtonConvertDER, javax.swing.GroupLayout.PREFERRED_SIZE, 189,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(46, 46, 46)));
		jPanel7Layout
				.setVerticalGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(jPanel7Layout.createSequentialGroup().addContainerGap().addGroup(jPanel7Layout
								.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE).addComponent(jLabel33)
								.addComponent(jTextFieldConvertSourceFile, javax.swing.GroupLayout.PREFERRED_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
								.addComponent(jButtonConvertSourceFile))
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jRadioButtonPEM).addComponent(jRadioButtonDER)
										.addComponent(jRadioButtonPEMorDER))
								.addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
						.addGroup(jPanel7Layout.createSequentialGroup().addGap(21, 21, 21)
								.addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jButtonConvertDER, javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
										.addComponent(jButtonConvertPEM, javax.swing.GroupLayout.DEFAULT_SIZE,
												javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
								.addContainerGap()));

		javax.swing.GroupLayout jPanel17Layout = new javax.swing.GroupLayout(jPanel17);
		jPanel17.setLayout(jPanel17Layout);
		jPanel17Layout.setHorizontalGroup(jPanel17Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addComponent(jPanel18, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
						Short.MAX_VALUE)
				.addGroup(jPanel17Layout.createSequentialGroup().addComponent(jPanel7,
						javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
						.addContainerGap()));
		jPanel17Layout.setVerticalGroup(jPanel17Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanel17Layout.createSequentialGroup()
						.addComponent(jPanel18, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(jPanel7, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(0, 197, Short.MAX_VALUE)));

		jTabbedPaneScreens.addTab("Convertir", jPanel17);

		jListEvents.setModel(new DefaultListModel<String>());
		jScrollPaneForEvents.setViewportView(jListEvents);

		javax.swing.GroupLayout jPanelEventsLayout = new javax.swing.GroupLayout(jPanelEvents);
		jPanelEvents.setLayout(jPanelEventsLayout);
		jPanelEventsLayout.setHorizontalGroup(jPanelEventsLayout
				.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(jPanelEventsLayout.createSequentialGroup()
						.addGroup(jPanelEventsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
								.addComponent(jProgressBarEnigma, javax.swing.GroupLayout.Alignment.LEADING,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
										Short.MAX_VALUE)
								.addComponent(jScrollPaneForEvents, javax.swing.GroupLayout.Alignment.LEADING))
						.addGap(0, 0, 0)));
		jPanelEventsLayout
				.setVerticalGroup(jPanelEventsLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
								jPanelEventsLayout.createSequentialGroup()
										.addComponent(jScrollPaneForEvents, javax.swing.GroupLayout.PREFERRED_SIZE, 104,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
										.addComponent(jProgressBarEnigma, javax.swing.GroupLayout.PREFERRED_SIZE, 16,
												javax.swing.GroupLayout.PREFERRED_SIZE)
										.addGap(0, 0, Short.MAX_VALUE)));

		jTextFieldGlobalOutput.setMargin(new java.awt.Insets(1, 5, 1, 1));

		jLabel38.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
		jLabel38.setText("Global Output Directory :");

		jButtonBrowseGlobalOutput.setBackground(new java.awt.Color(153, 153, 255));
		jButtonBrowseGlobalOutput.setForeground(new Color(0, 0, 0));
		jButtonBrowseGlobalOutput.setIcon(new javax.swing.ImageIcon(getClass().getResource("/look.png"))); // NOI18N
		jButtonBrowseGlobalOutput.setText("Set output dir");
		jButtonBrowseGlobalOutput.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseGlobalOutputActionPerformed(evt);
			}
		});

		jButtonBrowseGlobalOutput1.setBackground(new java.awt.Color(210, 134, 104));
		jButtonBrowseGlobalOutput1.setForeground(new Color(0, 0, 0));
		jButtonBrowseGlobalOutput1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/directory.png"))); // NOI18N
		jButtonBrowseGlobalOutput1.setText("Open Explorer");
		jButtonBrowseGlobalOutput1.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(java.awt.event.ActionEvent evt) {
				jButtonBrowseGlobalOutput1ActionPerformed(evt);
			}
		});

		javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(
				layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
						.addGroup(javax.swing.GroupLayout.Alignment.TRAILING,
								layout.createSequentialGroup().addGap(0, 4, Short.MAX_VALUE).addComponent(
										jTabbedPaneScreens, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
						.addComponent(jPanelEvents, javax.swing.GroupLayout.Alignment.TRAILING,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE,
								Short.MAX_VALUE)
						.addGroup(layout.createSequentialGroup().addContainerGap().addComponent(jLabel38)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jTextFieldGlobalOutput, javax.swing.GroupLayout.PREFERRED_SIZE, 1000,
										javax.swing.GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jButtonBrowseGlobalOutput, javax.swing.GroupLayout.DEFAULT_SIZE,
										javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
								.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
								.addComponent(jButtonBrowseGlobalOutput1).addContainerGap()));
		layout.setVerticalGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
				.addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
						.addComponent(jTabbedPaneScreens, javax.swing.GroupLayout.PREFERRED_SIZE, 693,
								javax.swing.GroupLayout.PREFERRED_SIZE)
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
								.addComponent(jButtonBrowseGlobalOutput1, javax.swing.GroupLayout.Alignment.TRAILING,
										javax.swing.GroupLayout.DEFAULT_SIZE, 31, Short.MAX_VALUE)
								.addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
										.addComponent(jTextFieldGlobalOutput, javax.swing.GroupLayout.PREFERRED_SIZE,
												30, javax.swing.GroupLayout.PREFERRED_SIZE)
										.addComponent(jLabel38).addComponent(jButtonBrowseGlobalOutput,
												javax.swing.GroupLayout.PREFERRED_SIZE, 30,
												javax.swing.GroupLayout.PREFERRED_SIZE)))
						.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
						.addComponent(jPanelEvents, javax.swing.GroupLayout.PREFERRED_SIZE,
								javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
						.addGap(0, 0, 0)));

		pack();
	}// </editor-fold>//GEN-END:initComponents

	private void jButton8ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton8ActionPerformed
		// TODO add your handling code here:
		FileAnalyzer analyzer = new FileAnalyzer(jTextFieldDrop.getText());
		for (String dd : analyzer.getResults()) {
			jEditorPaneIdentifierResults.setText(jEditorPaneIdentifierResults.getText() + dd + "\n");
		}
	}// GEN-LAST:event_jButton8ActionPerformed

	private void jButton7ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton7ActionPerformed
		int retour = jFileChooserFileOnly.showOpenDialog(this);
		if (retour == JFileChooser.APPROVE_OPTION) {
			jTextFieldDrop.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
		}
	}// GEN-LAST:event_jButton7ActionPerformed

	private void jButtonBrowseP10PkActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseP10PkActionPerformed

		jDialogFileImport.setVisible(true);
	}// GEN-LAST:event_jButtonBrowseP10PkActionPerformed

	private void jButtonPubGenerateActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonPubGenerateActionPerformed
		CryptoGenerator cg = new CryptoGenerator();
		String outRet = cg.generatePublicKeyFromPrivateKey((String) jComboBoxPubPK.getSelectedItem(),
				jTextFieldPubPrivkeyPW.getText(), jTextFieldGlobalOutput.getText(),
				jTextFieldPubTargetFilename.getText(), (String) jTextFieldPubTargetKeyName.getText());
		refreshX509KeyTable();
		refreshPubKObjects();
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonPubGenerateActionPerformed

	private void jComboBoxAlgoPkActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxAlgoPkActionPerformed
		if ("DH".equals(((String) jComboBoxAlgoPk.getSelectedItem()))) {
			jSpinnerKeySizePkSize.setEnabled(false);
			jSpinnerKeySizePkSize.setValue(2048);
		} else {
			jSpinnerKeySizePkSize.setEnabled(true);
		}
	}// GEN-LAST:event_jComboBoxAlgoPkActionPerformed

	private void jCheckBoxPkExpoActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxPkExpoActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jSpinnerPkExpo.setEnabled(false);
		} else {
			jSpinnerPkExpo.setEnabled(true);
		}
	}// GEN-LAST:event_jCheckBoxPkExpoActionPerformed

	private void jLabel15MouseEntered(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_jLabel15MouseEntered
		// TODO add your handling code here:
	}// GEN-LAST:event_jLabel15MouseEntered

	private void jCheckBoxPkCertaintyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxPkCertaintyActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jSliderPkCertainty.setEnabled(false);
		} else {
			jSliderPkCertainty.setEnabled(true);
		}
	}// GEN-LAST:event_jCheckBoxPkCertaintyActionPerformed

	private void jButtonPkGenerateActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonPkGenerateActionPerformed
		CryptoGenerator cg = new CryptoGenerator();
		String algo = String.valueOf(jComboBoxAlgoPk.getSelectedItem());
		String outRet = cg.buildPrivateKey(jTextFieldGlobalOutput.getText(), jTextFieldPkPw.getText(),
				jTextFieldPkTargetFilename.getText(), (int) jSpinnerKeySizePkSize.getValue(),
				Integer.toString((Integer) jSpinnerPkExpo.getValue()), jSliderPkCertainty.getValue(), algo,
				jTextFieldPkTargetKeyName.getText());
		refreshX509KeyTable();
		refreshPKObjects();
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonPkGenerateActionPerformed

	private void jButtonPKCS12GenerateActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonPKCS12GenerateActionPerformed
		// TODO add your handling code here:
		Integer pubExpo = (Integer) jSpinnerP12Expo.getValue();
		if (!jSpinnerP12Expo.isEnabled()) {
			pubExpo = new Integer(props.getProperty("defaultPublicExponent"));
		}
		int certainty = jSliderP12Certainty.getValue();
		if (!jSliderP12Certainty.isEnabled()) {
			certainty = Integer.parseInt(props.getProperty("defaultCertainty"));
		}
		CryptoGenerator.generatePKCS12((int) jSpinnerKeySize.getValue(), jTextFieldCN.getText(),
				jTextFieldKeystorePW.getText(), jTextFieldPKCS8PW.getText(), jTextFieldGlobalOutput.getText(),
				pubExpo.toString(), certainty, jDateChooserP12Expiry.getDate(), jTextFieldP12TargetFilename.getText(),
				jCheckBoxP12Write.isSelected(), (String) jComboBoxAC.getSelectedItem());
		((DefaultListModel) jListEvents.getModel()).addElement("PKCS#12 successfully generated for "
				+ jTextFieldCN.getText() + " in directory " + jTextFieldGlobalOutput.getText() + ".");
	}// GEN-LAST:event_jButtonPKCS12GenerateActionPerformed

	private void jCheckBoxP12CertaintyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxP12CertaintyActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jSliderP12Certainty.setEnabled(false);
		} else {
			jSliderP12Certainty.setEnabled(true);
		}
	}// GEN-LAST:event_jCheckBoxP12CertaintyActionPerformed

	private void jCheckBoxP12ExpoActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxP12ExpoActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jSpinnerP12Expo.setEnabled(false);
		} else {
			jSpinnerP12Expo.setEnabled(true);
		}
	}// GEN-LAST:event_jCheckBoxP12ExpoActionPerformed

	private void jLabel10MouseEntered(java.awt.event.MouseEvent evt) {// GEN-FIRST:event_jLabel10MouseEntered
		// TODO add your handling code here:
	}// GEN-LAST:event_jLabel10MouseEntered

	private void jComboBoxAlgoP12ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxAlgoP12ActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jComboBoxAlgoP12ActionPerformed

	private void jTextFieldKeystorePWActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldKeystorePWActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldKeystorePWActionPerformed

	private void jButtonCSRGenerateActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonCSRGenerateActionPerformed
		CryptoGenerator cg = new CryptoGenerator();
		String outRet = cg.buildCSRfromKeyPair(jTextFieldP10CN.getText(), ((String) jComboBoxCSRPk.getSelectedItem()),
				jTextFieldP10PkPw.getText(), (String) jComboBoxPubPK.getSelectedItem(),
				jTextFieldP10TargetFilename.getText(), jTextFieldGlobalOutput.getText());
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonCSRGenerateActionPerformed

	private void jCheckBoxP10PubKeyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxP10PubKeyActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jButtonBrowseP10PubK.setEnabled(true);
			jComboBoxCSRPubK.setEnabled(true);
		} else {
			jButtonBrowseP10PubK.setEnabled(false);
			jComboBoxCSRPubK.setEnabled(false);
		}
	}// GEN-LAST:event_jCheckBoxP10PubKeyActionPerformed

	private void jButtonConvertSourceFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonConvertSourceFileActionPerformed
		int retour = jFileChooserFileOnly.showOpenDialog(this);
		if (retour == JFileChooser.APPROVE_OPTION) {
			jTextFieldConvertSourceFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
		}
	}// GEN-LAST:event_jButtonConvertSourceFileActionPerformed

	private void jButtonBrowseCertPkActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseCertPkActionPerformed

		jDialogFileImport.setVisible(true);
	}// GEN-LAST:event_jButtonBrowseCertPkActionPerformed

	private void jButtonBrowseCertPubActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseCertPubActionPerformed
		jDialogFileImportPublic.setVisible(true);
	}// GEN-LAST:event_jButtonBrowseCertPubActionPerformed

	private void jButtonCertGenerateActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonCertGenerateActionPerformed
		CryptoGenerator cg = new CryptoGenerator();
		String outRet = cg.generateCertificateFromPublicKeyAndPrivateKey(jTextFieldCertCN.getText(),
				(String) jComboBoxCertPubK.getSelectedItem(), (String) jComboBoxCertPk.getSelectedItem(),
				jTextFieldCertPkPw.getText(), jTextFieldGlobalOutput.getText(), jTextFieldCertTargetFilename.getText(),
				jDateChooserExpiry.getDate(), (String) jComboBoxCertAlgo.getSelectedItem(),
				(String) jComboBoxCertVersion.getSelectedItem(), jTextFieldPubTargetCertName.getText());
		refreshX509CertOutline();
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonCertGenerateActionPerformed

	private void jButtonBrowseSignFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseSignFileActionPerformed
		int retour = jFileChooserFileOnly.showOpenDialog(this);
		if (retour == JFileChooser.APPROVE_OPTION) {
			// un fichier a été choisi (sortie par OK)
			// nom du fichier choisi
			// jFileChooser1.getSelectedFile().getName();
			// chemin absolu du fichier choisi
			jTextFieldSignFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
		} // TODO add your handling code here:
	}// GEN-LAST:event_jButtonBrowseSignFileActionPerformed

	private void jComboBoxAlgoSignActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxAlgoSignActionPerformed

	}// GEN-LAST:event_jComboBoxAlgoSignActionPerformed

	private void jButtonSignActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonSignActionPerformed
		CryptoGenerator cg = new CryptoGenerator();
		String algo = String.valueOf(jComboBoxAlgoSign.getSelectedItem());
		String outRet = cg.signFile(jTextFieldSignFile.getText(), (String) jComboBoxSignPK.getSelectedItem(),
				jTextFieldSignPkPassword.getText(), jTextFieldGlobalOutput.getText(),
				jTextFieldSignOutputFilename.getText(), algo, (String) jComboBoxSignSignerCert.getSelectedItem());
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonSignActionPerformed

	private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton1ActionPerformed
		jFrameAbout.setVisible(false);
	}// GEN-LAST:event_jButton1ActionPerformed

	private void jCheckBox2ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBox2ActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jTextFieldSignOutputFilename.setEnabled(true);
		} else {
			jTextFieldSignOutputFilename.setEnabled(false);
			jTextFieldSignOutputFilename.setText(getFileName(jTextFieldSignFile.getText()) + ".sig");
		}
	}// GEN-LAST:event_jCheckBox2ActionPerformed

	private void jTextFieldSignFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldSignFileActionPerformed

	}// GEN-LAST:event_jTextFieldSignFileActionPerformed

	private void jTextFieldSignFileInputMethodTextChanged(java.awt.event.InputMethodEvent evt) {// GEN-FIRST:event_jTextFieldSignFileInputMethodTextChanged

	}// GEN-LAST:event_jTextFieldSignFileInputMethodTextChanged

	private void jButtonDashAboutActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashAboutActionPerformed
		jFrameAbout.setDefaultCloseOperation(jFrameAbout.EXIT_ON_CLOSE);
		jFrameAbout.setVisible(true);
	}// GEN-LAST:event_jButtonDashAboutActionPerformed

	private void jButtonDashScenariosActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashScenariosActionPerformed
		// jTabbedPaneScreens.setSelectedIndex(6);
	}// GEN-LAST:event_jButtonDashScenariosActionPerformed

	private void jButtonDashPGPActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashPGPActionPerformed
		// jTabbedPaneScreens.setSelectedIndex(6);
	}// GEN-LAST:event_jButtonDashPGPActionPerformed

	private void jButtonDashX509ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashX509ActionPerformed
		jTabbedPaneScreens.setSelectedIndex(1);
	}// GEN-LAST:event_jButtonDashX509ActionPerformed

	private void jButtonDashConvertActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashConvertActionPerformed
		jTabbedPaneScreens.setSelectedIndex(5);
	}// GEN-LAST:event_jButtonDashConvertActionPerformed

	private void jButtonDashAnalyzeActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashAnalyzeActionPerformed
		jTabbedPaneScreens.setSelectedIndex(4);
	}// GEN-LAST:event_jButtonDashAnalyzeActionPerformed

	private void jButtonDashTransformActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashTransformActionPerformed
		jTabbedPaneScreens.setSelectedIndex(3);
	}// GEN-LAST:event_jButtonDashTransformActionPerformed

	private void jButtonDashGenerateActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDashGenerateActionPerformed
		// jTabbedPaneGenerate.setSelectedIndex(0);
		jTabbedPaneScreens.setSelectedIndex(2);
	}// GEN-LAST:event_jButtonDashGenerateActionPerformed

	private void jButtonDecodeBase64ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDecodeBase64ActionPerformed
		String b64datas = jTextAreaBase64Data.getText();
		if (b64datas != null && !"".equals(b64datas)) {
			byte[] valueDecoded = Base64.decode(b64datas);
			String decoded = new String(valueDecoded);
			jTextAreaOriginalData.setText(decoded);
		}
	}// GEN-LAST:event_jButtonDecodeBase64ActionPerformed

	private void jButtonEncodeBase64ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonEncodeBase64ActionPerformed
		String originalDatas = jTextAreaOriginalData.getText();
		if (originalDatas != null && !"".equals(originalDatas)) {
			byte[] valueEncoded = Base64.encode(originalDatas.getBytes());
			String encoded = new String(valueEncoded);
			jTextAreaBase64Data.setText(encoded);
		}
	}// GEN-LAST:event_jButtonEncodeBase64ActionPerformed

	private void jButton15ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton15ActionPerformed

		jFrameSignature.setVisible(true);
	}// GEN-LAST:event_jButton15ActionPerformed

	private void jButton16ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton16ActionPerformed

		jFrameX509vsPGP.setVisible(true);
	}// GEN-LAST:event_jButton16ActionPerformed

	private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton4ActionPerformed
		jFrameSignature.setVisible(false);
	}// GEN-LAST:event_jButton4ActionPerformed

	private void jButton5ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton5ActionPerformed
		jFrameX509vsPGP.setVisible(false);
	}// GEN-LAST:event_jButton5ActionPerformed

	private void jTextFieldP10PkPwActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldP10PkPwActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldP10PkPwActionPerformed

	private void jButtonBrowsePubPkActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowsePubPkActionPerformed

		jDialogFileImport.setVisible(true);

	}// GEN-LAST:event_jButtonBrowsePubPkActionPerformed

	private void jComboBoxCertAlgoActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxCertAlgoActionPerformed

	}// GEN-LAST:event_jComboBoxCertAlgoActionPerformed

	private void jButtonKeyNameActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonKeyNameActionPerformed
		jDialogFileImport.setVisible(false);
		if (!"".equals(jTextFieldImportKeyName.getText())) {
			CryptoGenerator cg = new CryptoGenerator();
			String outRet = null;
			try {
				outRet = cg.importPrivateKey(jFileChooserFileOnly.getSelectedFile().getAbsolutePath(),
						jTextFieldImportKeyName.getText());
			} catch (EnigmaException ex) {
				outRet = ex.getMsg();
			}
			refreshPKObjects();
			refreshX509KeyTable();
			((DefaultListModel) jListEvents.getModel()).addElement(outRet);
		}
	}// GEN-LAST:event_jButtonKeyNameActionPerformed

	private void jButtonImportKeyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonImportKeyActionPerformed
		int retour = jFileChooserFileOnly.showOpenDialog(this);
		if (retour == JFileChooser.APPROVE_OPTION) {
			jTextFieldImportKeyFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
		}
	}// GEN-LAST:event_jButtonImportKeyActionPerformed

	private void jButtonKeyName1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonKeyName1ActionPerformed
		jDialogFileImportPublic.setVisible(false);
		if (!"".equals(jTextFieldImportKeyName.getText())) {
			CryptoGenerator cg = new CryptoGenerator();
			String outRet = null;
			try {
				outRet = cg.importPublicKey(jFileChooserFileOnly.getSelectedFile().getAbsolutePath(),
						jTextFieldImportKeyName.getText());
			} catch (EnigmaException ex) {
				outRet = ex.getMsg();
			}
			refreshPubKObjects();
			refreshX509KeyTable();
			((DefaultListModel) jListEvents.getModel()).addElement(outRet);
		}
	}// GEN-LAST:event_jButtonKeyName1ActionPerformed

	private void jButtonImportKey1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonImportKey1ActionPerformed
		int retour = jFileChooserFileOnly.showOpenDialog(this);
		if (retour == JFileChooser.APPROVE_OPTION) {
			jTextFieldImportKeyFile1.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
		}
	}// GEN-LAST:event_jButtonImportKey1ActionPerformed

	private void jComboBoxCertVersionActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxCertVersionActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jComboBoxCertVersionActionPerformed

	private void jButtonBrowseP10PubKActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseP10PubKActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jButtonBrowseP10PubKActionPerformed

	private void jRadioButtonPEMActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonPEMActionPerformed
		if (jRadioButtonPEM.isSelected()) {
			jButtonConvertPEM.setEnabled(false);
			jButtonConvertDER.setEnabled(true);
		}
	}// GEN-LAST:event_jRadioButtonPEMActionPerformed

	private void jRadioButtonDERActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonDERActionPerformed
		if (jRadioButtonDER.isSelected()) {
			jButtonConvertPEM.setEnabled(true);
			jButtonConvertDER.setEnabled(false);
		}
	}// GEN-LAST:event_jRadioButtonDERActionPerformed

	private void jRadioButtonPEMorDERActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonPEMorDERActionPerformed
		if (jRadioButtonPEMorDER.isSelected()) {
			jButtonConvertPEM.setEnabled(true);
			jButtonConvertDER.setEnabled(true);
		}
	}// GEN-LAST:event_jRadioButtonPEMorDERActionPerformed

	private void jButtonConvertPEMActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonConvertPEMActionPerformed
		// TODO add your handling code here:
		ExportManager xm = new ExportManager();
		String outRet = xm.convertDERtoPEM(jTextFieldConvertSourceFile.getText());
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonConvertPEMActionPerformed

	private void jButtonConvertDERActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonConvertDERActionPerformed
		// TODO add your handling code here:
		ExportManager xm = new ExportManager();
		String outRet = xm.convertPEMToDER(jTextFieldConvertSourceFile.getText());
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonConvertDERActionPerformed

	private void jComboBoxACActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxACActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jComboBoxACActionPerformed

	private void jTextFieldCipherFileInputMethodTextChanged(java.awt.event.InputMethodEvent evt) {// GEN-FIRST:event_jTextFieldCipherFileInputMethodTextChanged
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldCipherFileInputMethodTextChanged

	private void jTextFieldCipherFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldCipherFileActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldCipherFileActionPerformed

	private void jButtonBrowseCipherFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseCipherFileActionPerformed
		int retour = jFileChooserFileOnly.showOpenDialog(this);
		if (retour == JFileChooser.APPROVE_OPTION) {
			// un fichier a été choisi (sortie par OK)
			// nom du fichier choisi
			// jFileChooser1.getSelectedFile().getName();
			// chemin absolu du fichier choisi
			jTextFieldCipherFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
		} // TODO add your handling code here:
	}// GEN-LAST:event_jButtonBrowseCipherFileActionPerformed

	private void jButtonCipherActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonCipherActionPerformed
		CryptoGenerator cg = new CryptoGenerator();
		String outRet = cg.cipherFile(jTextFieldCipherFile.getText(), (String) jComboBoxCipherCert.getSelectedItem(),
				jTextFieldGlobalOutput.getText(), jTextFieldCipherOutputFilename.getText(),
				(String) jComboBoxAlgoCipher.getSelectedItem());
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonCipherActionPerformed

	private void jComboBoxAlgoCipherActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxAlgoCipherActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jComboBoxAlgoCipherActionPerformed

	private void jCheckBoxCustomCipherActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxCustomCipherActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jTextFieldCipherOutputFilename.setEnabled(true);
		} else {
			jTextFieldCipherOutputFilename.setEnabled(false);
			jTextFieldCipherOutputFilename.setText(getFileName(jTextFieldCipherFile.getText()) + ".sig");
		}
	}// GEN-LAST:event_jCheckBoxCustomCipherActionPerformed

	private void jButtonBrowseGlobalOutputActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseGlobalOutputActionPerformed
		int retour = jFileChooserDirectoriesOnly.showOpenDialog(this);
		if (retour == JFileChooser.APPROVE_OPTION) {
			// un fichier a été choisi (sortie par OK)
			// nom du fichier choisi
			// jFileChooser1.getSelectedFile().getName();
			// chemin absolu du fichier choisi
			jTextFieldGlobalOutput.setText(jFileChooserDirectoriesOnly.getSelectedFile().getAbsolutePath() + "\\");
		}
	}// GEN-LAST:event_jButtonBrowseGlobalOutputActionPerformed

	private void jTextFieldSignOutputFilenameActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldSignOutputFilenameActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldSignOutputFilenameActionPerformed

	private void jButtonBrowseGlobalOutput1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseGlobalOutput1ActionPerformed
		try {
			Desktop.getDesktop().open(new File(jTextFieldGlobalOutput.getText()));
		} catch (IOException ex) {
			Logger.getLogger(EnigmaIHM.class.getName()).log(Level.SEVERE, null, ex);
		}
	}// GEN-LAST:event_jButtonBrowseGlobalOutput1ActionPerformed

	private void jTextFieldVerifyFileInputMethodTextChanged(java.awt.event.InputMethodEvent evt) {// GEN-FIRST:event_jTextFieldVerifyFileInputMethodTextChanged
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldVerifyFileInputMethodTextChanged

	private void jTextFieldVerifyFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldVerifyFileActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldVerifyFileActionPerformed

	private void jButtonBrowseVerifyFileActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseVerifyFileActionPerformed
		int retour = jFileChooserFileOnly.showOpenDialog(this);
		if (retour == JFileChooser.APPROVE_OPTION) {
			// un fichier a été choisi (sortie par OK)
			// nom du fichier choisi
			// jFileChooser1.getSelectedFile().getName();
			// chemin absolu du fichier choisi
			jTextFieldVerifyFile.setText(jFileChooserFileOnly.getSelectedFile().getAbsolutePath());
		} // TODO add your handling code here:
	}// GEN-LAST:event_jButtonBrowseVerifyFileActionPerformed

	private void jButtonValidateActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonValidateActionPerformed

	}// GEN-LAST:event_jButtonValidateActionPerformed

	private void jCheckBoxCustomVerifyTryAllActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxCustomVerifyTryAllActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jComboBoxVerifyCert.setEnabled(true);
		} else {
			jComboBoxVerifyCert.setEnabled(false);
		}
	}// GEN-LAST:event_jCheckBoxCustomVerifyTryAllActionPerformed

	private void jCheckBoxCustomVerifyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxCustomVerifyActionPerformed
		JCheckBox cbLog = (JCheckBox) evt.getSource();
		if (cbLog.isSelected()) {
			jTextFieldVerifyOutputFilename.setEnabled(true);
		} else {
			jTextFieldVerifyOutputFilename.setEnabled(false);
			jTextFieldVerifyOutputFilename.setText(getFileName(jTextFieldVerifyOutputFilename.getText()) + ".sig");
		}
	}// GEN-LAST:event_jCheckBoxCustomVerifyActionPerformed

	private void jButtonVerifyActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonVerifyActionPerformed
		CryptoGenerator cg = new CryptoGenerator();
		String outRet = cg.verifyFile(jTextFieldVerifyFile.getText(), (String) jComboBoxVerifyCert.getSelectedItem(),
				jTextFieldGlobalOutput.getText(), jTextFieldVerifyOutputFilename.getText(),
				jCheckBoxCustomVerifyTryAll.isSelected());
		((DefaultListModel) jListEvents.getModel()).addElement(outRet);
	}// GEN-LAST:event_jButtonVerifyActionPerformed

	private void jTextFieldSignFile1InputMethodTextChanged(java.awt.event.InputMethodEvent evt) {// GEN-FIRST:event_jTextFieldSignFile1InputMethodTextChanged
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldSignFile1InputMethodTextChanged

	private void jTextFieldSignFile1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldSignFile1ActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldSignFile1ActionPerformed

	private void jButtonBrowseSignFile1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBrowseSignFile1ActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jButtonBrowseSignFile1ActionPerformed

	private void jTextFieldDecryptOutputFilenameActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldDecryptOutputFilenameActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jTextFieldDecryptOutputFilenameActionPerformed

	private void jCheckBoxCustomDecryptActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jCheckBoxCustomDecryptActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jCheckBoxCustomDecryptActionPerformed

	private void jButtonDecryptActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDecryptActionPerformed
		// TODO add your handling code here:
	}// GEN-LAST:event_jButtonDecryptActionPerformed

	/**
	 * @param args the command line arguments
	 */
	public static void main(String args[]) {
		/* Set the Nimbus look and feel */
		// <editor-fold defaultstate="collapsed" desc=" Look and feel setting code
		// (optional) ">
		/*
		 * If Nimbus (introduced in Java SE 6) is not available, stay with the default
		 * look and feel. For details see
		 * http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
		 */
		try {
			for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
				System.out.println("org.caulfield.enigma.EnigmaIHM.main():" + info.getName());
				if ("Windows".equals(info.getName())) {
					javax.swing.UIManager.setLookAndFeel(info.getClassName());
					break;
				}
			}
		} catch (ClassNotFoundException ex) {
			java.util.logging.Logger.getLogger(EnigmaIHM.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
		} catch (InstantiationException ex) {
			java.util.logging.Logger.getLogger(EnigmaIHM.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
		} catch (IllegalAccessException ex) {
			java.util.logging.Logger.getLogger(EnigmaIHM.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
		} catch (javax.swing.UnsupportedLookAndFeelException ex) {
			java.util.logging.Logger.getLogger(EnigmaIHM.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
		}
		// </editor-fold>

		/* Create and display the form */
		java.awt.EventQueue.invokeLater(new Runnable() {
			public void run() {
				new EnigmaIHM().setVisible(true);
			}
		});
	}

	private javax.swing.JButton jButton1;
	private javax.swing.JButton jButton10;
	private javax.swing.JButton jButton11;
	private javax.swing.JButton jButton12;
	private javax.swing.JButton jButton13;
	private javax.swing.JButton jButton14;
	private javax.swing.JButton jButton15;
	private javax.swing.JButton jButton16;
	private javax.swing.JButton jButton4;
	private javax.swing.JButton jButton5;
	private javax.swing.JButton jButton7;
	private javax.swing.JButton jButton8;
	private javax.swing.JButton jButtonBrowseCertPk;
	private javax.swing.JButton jButtonBrowseCertPub;
	private javax.swing.JButton jButtonBrowseCipherFile;
	private javax.swing.JButton jButtonBrowseGlobalOutput;
	private javax.swing.JButton jButtonBrowseGlobalOutput1;
	private javax.swing.JButton jButtonBrowseP10Pk;
	private javax.swing.JButton jButtonBrowseP10PubK;
	private javax.swing.JButton jButtonBrowsePubPk;
	private javax.swing.JButton jButtonBrowseSignFile;
	private javax.swing.JButton jButtonBrowseSignFile1;
	private javax.swing.JButton jButtonBrowseVerifyFile;
	private javax.swing.JButton jButtonCSRGenerate;
	private javax.swing.JButton jButtonCertGenerate;
	private javax.swing.JButton jButtonCipher;
	private javax.swing.JButton jButtonConvertDER;
	private javax.swing.JButton jButtonConvertPEM;
	private javax.swing.JButton jButtonConvertSourceFile;
	private javax.swing.JButton jButtonDashAbout;
	private javax.swing.JButton jButtonDashAnalyze;
	private javax.swing.JButton jButtonDashConvert;
	private javax.swing.JButton jButtonDashGenerate;
	private javax.swing.JButton jButtonDashPGP;
	private javax.swing.JButton jButtonDashScenarios;
	private javax.swing.JButton jButtonDashTransform;
	private javax.swing.JButton jButtonDashX509;
	private javax.swing.JButton jButtonDecodeBase64;
	private javax.swing.JButton jButtonDecrypt;
	private javax.swing.JButton jButtonEncodeBase64;
	private javax.swing.JButton jButtonImportKey;
	private javax.swing.JButton jButtonImportKey1;
	private javax.swing.JButton jButtonKeyName;
	private javax.swing.JButton jButtonKeyName1;
	private javax.swing.JButton jButtonPKCS12Generate;
	private javax.swing.JButton jButtonPkGenerate;
	private javax.swing.JButton jButtonPubGenerate;
	private javax.swing.JButton jButtonSign;
	private javax.swing.JButton jButtonValidate;
	private javax.swing.JButton jButtonVerify;
	private javax.swing.JCheckBox jCheckBox2;
	private javax.swing.JCheckBox jCheckBoxCustomCipher;
	private javax.swing.JCheckBox jCheckBoxCustomDecrypt;
	private javax.swing.JCheckBox jCheckBoxCustomVerify;
	private javax.swing.JCheckBox jCheckBoxCustomVerifyTryAll;
	private javax.swing.JCheckBox jCheckBoxP10PubKey;
	private javax.swing.JCheckBox jCheckBoxP12Certainty;
	private javax.swing.JCheckBox jCheckBoxP12Expo;
	private javax.swing.JCheckBox jCheckBoxP12Write;
	private javax.swing.JCheckBox jCheckBoxPkCertainty;
	private javax.swing.JCheckBox jCheckBoxPkExpo;
	private javax.swing.JComboBox<String> jComboBoxAC;
	private javax.swing.JComboBox<String> jComboBoxAlgoCipher;
	private javax.swing.JComboBox<String> jComboBoxAlgoP12;
	private javax.swing.JComboBox<String> jComboBoxAlgoPk;
	private javax.swing.JComboBox<String> jComboBoxAlgoSign;
	private javax.swing.JComboBox<String> jComboBoxCSRPk;
	private javax.swing.JComboBox<String> jComboBoxCSRPubK;
	private javax.swing.JComboBox<String> jComboBoxCertAlgo;
	private javax.swing.JComboBox<String> jComboBoxCertPk;
	private javax.swing.JComboBox<String> jComboBoxCertPubK;
	private javax.swing.JComboBox<String> jComboBoxCertVersion;
	private javax.swing.JComboBox<String> jComboBoxCipherCert;
	private javax.swing.JComboBox<String> jComboBoxPubPK;
	private javax.swing.JComboBox<String> jComboBoxSignPK;
	private javax.swing.JComboBox<String> jComboBoxCipher;
	private javax.swing.JComboBox<String> jComboBoxSignSignerCert;
	private javax.swing.JComboBox<String> jComboBoxVerifyCert;
	private com.toedter.calendar.JDateChooser jDateChooserExpiry;
	private com.toedter.calendar.JDateChooser jDateChooserP12Expiry;
	private javax.swing.JDialog jDialogFileImport;
	private javax.swing.JDialog jDialogFileImportPublic;
	private javax.swing.JEditorPane jEditorPaneIdentifierResults;
	private javax.swing.JFileChooser jFileChooserDirectoriesOnly;
	private javax.swing.JFileChooser jFileChooserExportCRL;
	private javax.swing.JFileChooser jFileChooserExportCert;
	private javax.swing.JFileChooser jFileChooserFileOnly;
	private javax.swing.JFrame jFrameAbout;
	private javax.swing.JFrame jFrameSignature;
	private javax.swing.JFrame jFrameX509vsPGP;
	private javax.swing.JLabel jLabel1;
	private javax.swing.JLabel jLabel10;
	private javax.swing.JLabel jLabel11;
	private javax.swing.JLabel jLabel12;
	private javax.swing.JLabel jLabel14;
	private javax.swing.JLabel jLabel15;
	private javax.swing.JLabel jLabel16;
	private javax.swing.JLabel jLabel17;
	private javax.swing.JLabel jLabel18;
	private javax.swing.JLabel jLabel19;
	private javax.swing.JLabel jLabel2;
	private javax.swing.JLabel jLabel20;
	private javax.swing.JLabel jLabel21;
	private javax.swing.JLabel jLabel22;
	private javax.swing.JLabel jLabel23;
	private javax.swing.JLabel jLabel24;
	private javax.swing.JLabel jLabel25;
	private javax.swing.JLabel jLabel26;
	private javax.swing.JLabel jLabel27;
	private javax.swing.JLabel jLabel28;
	private javax.swing.JLabel jLabel3;
	private javax.swing.JLabel jLabel30;
	private javax.swing.JLabel jLabel31;
	private javax.swing.JLabel jLabel32;
	private javax.swing.JLabel jLabel33;
	private javax.swing.JLabel jLabel34;
	private javax.swing.JLabel jLabel36;
	private javax.swing.JLabel jLabel37;
	private javax.swing.JLabel jLabel38;
	private javax.swing.JLabel jLabel4;
	private javax.swing.JLabel jLabel40;
	private javax.swing.JLabel jLabel41;
	private javax.swing.JLabel jLabel42;
	private javax.swing.JLabel jLabel43;
	private javax.swing.JLabel jLabel44;
	private javax.swing.JLabel jLabel45;
	private javax.swing.JLabel jLabel46;
	private javax.swing.JLabel jLabel47;
	private javax.swing.JLabel jLabel48;
	private javax.swing.JLabel jLabel49;
	private javax.swing.JLabel jLabel5;
	private javax.swing.JLabel jLabel50;
	private javax.swing.JLabel jLabel51;
	private javax.swing.JLabel jLabel52;
	private javax.swing.JLabel jLabel53;
	private javax.swing.JLabel jLabel54;
	private javax.swing.JLabel jLabel55;
	private javax.swing.JLabel jLabel56;
	private javax.swing.JLabel jLabel57;
	private javax.swing.JLabel jLabel58;
	private javax.swing.JLabel jLabel59;
	private javax.swing.JLabel jLabel6;
	private javax.swing.JLabel jLabel60;
	private javax.swing.JLabel jLabel61;
	private javax.swing.JLabel jLabel62;
	private javax.swing.JLabel jLabel63;
	private javax.swing.JLabel jLabel64;
	private javax.swing.JLabel jLabel65;
	private javax.swing.JLabel jLabel66;
	private javax.swing.JLabel jLabel67;
	private javax.swing.JLabel jLabel68;
	private javax.swing.JLabel jLabel69;
	private javax.swing.JLabel jLabel7;
	private javax.swing.JLabel jLabel70;
	private javax.swing.JLabel jLabel71;
	private javax.swing.JLabel jLabel72;
	private javax.swing.JLabel jLabel73;
	private javax.swing.JLabel jLabel74;
	private javax.swing.JLabel jLabel75;
	private javax.swing.JLabel jLabel8;
	private javax.swing.JLabel jLabel9;
	private javax.swing.JList<String> jListEvents;
	private javax.swing.JPanel jPanel1;
	private javax.swing.JPanel jPanel10;
	private javax.swing.JPanel jPanel11;
	private javax.swing.JPanel jPanel12;
	private javax.swing.JPanel jPanel13;
	private javax.swing.JPanel jPanel14;
	private javax.swing.JPanel jPanel15;
	private javax.swing.JPanel jPanel16;
	private javax.swing.JPanel jPanel17;
	private javax.swing.JPanel jPanel18;
	private javax.swing.JPanel jPanel19;
	private javax.swing.JPanel jPanel2;
	private javax.swing.JPanel jPanel20;
	private javax.swing.JPanel jPanel21;
	private javax.swing.JPanel jPanel3;
	private javax.swing.JPanel jPanel4;
	private javax.swing.JPanel jPanel5;
	private javax.swing.JPanel jPanel6;
	private javax.swing.JPanel jPanel7;
	private javax.swing.JPanel jPanel9;
	private javax.swing.JPanel jPanelACManagement;
	private javax.swing.JPanel jPanelAnalyze;
	private javax.swing.JPanel jPanelDashboard;
	private javax.swing.JPanel jPanelEvents;
	private javax.swing.JPanel jPanelPGPKeyring;
	private javax.swing.JPanel jPanelScenarios;
	private javax.swing.JPanel jPanelSignature;
	private javax.swing.JPanel jPanelTransform;
	private javax.swing.JPanel jPanelX509vsPGP;
	private javax.swing.JProgressBar jProgressBarEnigma;
	private javax.swing.JRadioButton jRadioButtonDER;
	private javax.swing.JRadioButton jRadioButtonPEM;
	private javax.swing.JRadioButton jRadioButtonPEMorDER;
	private javax.swing.JScrollPane jScrollPane1;
	private javax.swing.JScrollPane jScrollPane2;
	private javax.swing.JScrollPane jScrollPane3;
	private javax.swing.JScrollPane jScrollPane4;
	private javax.swing.JScrollPane jScrollPane5;
	private javax.swing.JScrollPane jScrollPane6;
	private javax.swing.JScrollPane jScrollPane7;
	private javax.swing.JScrollPane jScrollPane8;
	private javax.swing.JScrollPane jScrollPane9;
	private javax.swing.JScrollPane jScrollPaneForEvents;
	private javax.swing.JSlider jSliderP12Certainty;
	private javax.swing.JSlider jSliderPkCertainty;
	private javax.swing.JSpinner jSpinnerKeySize;
	private javax.swing.JSpinner jSpinnerKeySizePkSize;
	private javax.swing.JSpinner jSpinnerP12Expo;
	private javax.swing.JSpinner jSpinnerPkExpo;
	private javax.swing.JTabbedPane jTabbedPane1;
	private javax.swing.JTabbedPane jTabbedPaneGenerate;
	private javax.swing.JTabbedPane jTabbedPaneScreens;
	private javax.swing.JTable jTableCRL;
	private javax.swing.JTable jTablePK;
	private javax.swing.JTextArea jTextArea2;
	private javax.swing.JTextArea jTextArea3;
	private javax.swing.JTextArea jTextAreaBase64Data;
	private javax.swing.JTextArea jTextAreaDrop;
	private javax.swing.JTextArea jTextAreaOriginalData;
	private javax.swing.JTextField jTextFieldCN;
	private javax.swing.JTextField jTextFieldCertCN;
	private javax.swing.JTextField jTextFieldCertPkPw;
	private javax.swing.JTextField jTextFieldCertTargetFilename;
	private javax.swing.JTextField jTextFieldCipherFile;
	private javax.swing.JTextField jTextFieldCipherOutputFilename;
	private javax.swing.JTextField jTextFieldConvertSourceFile;
	private javax.swing.JTextField jTextFieldDecryptOutputFilename;
	private javax.swing.JTextField jTextFieldDrop;
	private javax.swing.JTextField jTextFieldGlobalOutput;
	private javax.swing.JTextField jTextFieldImportKeyFile;
	private javax.swing.JTextField jTextFieldImportKeyFile1;
	private javax.swing.JTextField jTextFieldImportKeyName;
	private javax.swing.JTextField jTextFieldImportKeyName1;
	private javax.swing.JTextField jTextFieldKeystorePW;
	private javax.swing.JTextField jTextFieldP10CN;
	private javax.swing.JTextField jTextFieldP10PkPw;
	private javax.swing.JTextField jTextFieldP10TargetFilename;
	private javax.swing.JTextField jTextFieldP12TargetFilename;
	private javax.swing.JTextField jTextFieldPKCS8PW;
	private javax.swing.JTextField jTextFieldPkPw;
	private javax.swing.JTextField jTextFieldPkTargetFilename;
	private javax.swing.JTextField jTextFieldPkTargetKeyName;
	private javax.swing.JTextField jTextFieldPubPrivkeyPW;
	private javax.swing.JTextField jTextFieldPubTargetCertName;
	private javax.swing.JTextField jTextFieldPubTargetFilename;
	private javax.swing.JTextField jTextFieldPubTargetKeyName;
	private javax.swing.JTextField jTextFieldSignFile;
	private javax.swing.JTextField jTextFieldSignFile1;
	private javax.swing.JTextField jTextFieldSignOutputFilename;
	private javax.swing.JTextField jTextFieldSignPkPassword;
	private javax.swing.JTextField jTextFieldSignPkPassword1;
	private javax.swing.JTextField jTextFieldVerifyFile;
	private javax.swing.JTextField jTextFieldVerifyOutputFilename;
	private org.netbeans.swing.outline.Outline outline;
	// End of variables declaration//GEN-END:variables

}
