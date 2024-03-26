#ifndef CREDENTIALWIDGET_H
#define CREDENTIALWIDGET_H

#include <QWidget>

namespace Ui {
class CredentialWidget;
}

class CredentialWidget : public QWidget
{
    Q_OBJECT

public:
    explicit CredentialWidget(const QString &site, int id, QWidget *parent = nullptr);
    ~CredentialWidget();

    QString site() const;

signals:
    void decryptLogin(int id);
    void decryptPassword(int id);

private slots:
    void on_btnLoginCopy_clicked();
    void on_btnPassCopy_clicked();

private:
    Ui::CredentialWidget *ui;
    int m_id;
};

#endif // CREDENTIALWIDGET_H
