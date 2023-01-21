using System.Windows;
using System.Windows.Input;

namespace server_client_key_exchange{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow{
        public MainWindow() {
            InitializeComponent();
        }

        private void BtnHost_onClick(object sender, RoutedEventArgs e) {
            var server = new Server();
            server.Show();
        }

        private void BtnConnect_onClick(object sender, RoutedEventArgs e) {
            var client = new Client();
            client.Show();
        }

        private void UIElement_OnMouseLeftButtonDown(object sender, MouseButtonEventArgs e) {
            try {
                if (e.ChangedButton == MouseButton.Left)
                    DragMove();
            }
            catch (System.Exception) {
                //IGNORE
            }
           
            
        }

        private void BtnExit_onClick(object sender, RoutedEventArgs e) {
            Application.Current.Shutdown();
        }
    }
}