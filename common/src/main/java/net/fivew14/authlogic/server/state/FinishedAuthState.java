package net.fivew14.authlogic.server.state;

public class FinishedAuthState extends CommonAuthState {
    @Override
    public boolean isAuthenticated() {
        return true;
//        return this.authentication.isAuthenticated();
    }

    @Override
    public boolean isFinished() {
        return true;
    }
}
