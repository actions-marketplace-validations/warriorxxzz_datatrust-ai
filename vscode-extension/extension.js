const vscode = require('vscode');
const { execFile } = require('child_process');

function activate(context) {
    let disposable = vscode.commands.registerCommand('datatrust.scan', function () {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;

        const filepath = editor.document.uri.fsPath;
        execFile('datatrust', ['-f', filepath], (error, stdout, stderr) => {
            if (stdout) {
                vscode.window.showInformationMessage('DataTrust Scan Complete');
                const outputChannel = vscode.window.createOutputChannel("DataTrust AI");
                outputChannel.clear();
                outputChannel.appendLine(stdout);
                outputChannel.show();
            }
        });
    });

    context.subscriptions.push(disposable);

    vscode.workspace.onDidSaveTextDocument((document) => {
        const filepath = document.uri.fsPath;
        if (filepath.endsWith('.py') || filepath.endsWith('.js') || filepath.endsWith('.env')) {
            execFile('datatrust', ['-f', filepath], (error, stdout, stderr) => {
                if (error) {
                    vscode.window.showWarningMessage('🛑 DataTrust: Sensitive info found!');
                }
            });
        }
    });
}

function deactivate() {}
module.exports = { activate, deactivate }
