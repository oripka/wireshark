/* packet_format_group_box.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_format_group_box.h"
#include <ui_packet_format_group_box.h>

#include <epan/print.h>

#include <QStyle>
#include <QStyleOption>

PacketFormatGroupBox::PacketFormatGroupBox(QWidget *parent) :
    QGroupBox(parent),
    pf_ui_(new Ui::PacketFormatGroupBox)
{
    pf_ui_->setupUi(this);
    setFlat(true);

    QStyleOption style_opt;
    int cb_label_offset =  pf_ui_->detailsCheckBox->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left();

    // Indent the checkbox under the "Packet summary" checkbox
    pf_ui_->includeColumnHeadingsCheckBox->setStyleSheet(QStringLiteral(
                      "QCheckBox {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));

    // Indent the radio buttons under the "Packet details" checkbox
    pf_ui_->allCollapsedButton->setStyleSheet(QStringLiteral(
                      "QRadioButton {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));
    pf_ui_->asDisplayedButton->setStyleSheet(QStringLiteral(
                      "QRadioButton {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));
    pf_ui_->allExpandedButton->setStyleSheet(QStringLiteral(
                      "QRadioButton {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));

    // Indent the checkbox under the "Bytes" checkbox
    pf_ui_->includeDataSourcesCheckBox->setStyleSheet(QStringLiteral(
                      "QCheckBox {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));

    pf_ui_->timestampCheckBox->setStyleSheet(QStringLiteral(
                      "QCheckBox {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));
}

PacketFormatGroupBox::~PacketFormatGroupBox()
{
    delete pf_ui_;
}

bool PacketFormatGroupBox::summaryEnabled()
{
    return pf_ui_->summaryCheckBox->isChecked();
}

bool PacketFormatGroupBox::detailsEnabled()
{
    return pf_ui_->detailsCheckBox->isChecked();
}

bool PacketFormatGroupBox::bytesEnabled()
{
    return pf_ui_->bytesCheckBox->isChecked();
}

bool PacketFormatGroupBox::includeColumnHeadingsEnabled()
{
    return pf_ui_->includeColumnHeadingsCheckBox->isChecked();
}

bool PacketFormatGroupBox::allCollapsedEnabled()
{
    return pf_ui_->allCollapsedButton->isChecked();
}

bool PacketFormatGroupBox::asDisplayedEnabled()
{
    return pf_ui_->asDisplayedButton->isChecked();
}

bool PacketFormatGroupBox::allExpandedEnabled()
{
    return pf_ui_->allExpandedButton->isChecked();
}

uint PacketFormatGroupBox::getHexdumpOptions()
{
    return (pf_ui_->includeDataSourcesCheckBox->isChecked() ? HEXDUMP_SOURCE_MULTI : HEXDUMP_SOURCE_PRIMARY) | (pf_ui_->timestampCheckBox->isChecked() ? HEXDUMP_TIMESTAMP : HEXDUMP_TIMESTAMP_NONE);
}

void PacketFormatGroupBox::on_summaryCheckBox_toggled(bool checked)
{
    pf_ui_->includeColumnHeadingsCheckBox->setEnabled(checked);
    emit formatChanged();
}

void PacketFormatGroupBox::on_detailsCheckBox_toggled(bool checked)
{
    pf_ui_->allCollapsedButton->setEnabled(checked);
    pf_ui_->asDisplayedButton->setEnabled(checked);
    pf_ui_->allExpandedButton->setEnabled(checked);
    emit formatChanged();
}

void PacketFormatGroupBox::on_bytesCheckBox_toggled(bool checked)
{
    pf_ui_->includeDataSourcesCheckBox->setEnabled(checked);
    pf_ui_->timestampCheckBox->setEnabled(checked);
    emit formatChanged();
}

void PacketFormatGroupBox::on_includeColumnHeadingsCheckBox_toggled(bool)
{
    emit formatChanged();
}

void PacketFormatGroupBox::on_allCollapsedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatGroupBox::on_asDisplayedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatGroupBox::on_allExpandedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatGroupBox::on_includeDataSourcesCheckBox_toggled(bool)
{
    emit formatChanged();
}

void PacketFormatGroupBox::on_timestampCheckBox_toggled(bool)
{
    emit formatChanged();
}
