package net.fivew14.authlogic.server.state;

public class InProgressAuthState extends CommonAuthState {
    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public boolean isFinished() {
        return false;
    }
}
