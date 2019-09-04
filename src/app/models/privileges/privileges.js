import _ from 'lodash';
import { SFItem } from '../../models/item';

export class SFPrivileges extends SFItem {
  static contentType() {
    // It has prefix SN since it was originally imported from SN codebase
    return 'SN|Privileges';
  }

  constructor(jsonObj) {
    super(jsonObj);

    if (!this.content.desktopPrivileges) {
      this.content.desktopPrivileges = {};
    }
  }

  setCredentialsForAction(action, credentials) {
    this.content.desktopPrivileges[action] = credentials;
  }

  getCredentialsForAction(action) {
    return this.content.desktopPrivileges[action] || [];
  }

  toggleCredentialForAction(action, credential) {
    if (this.isCredentialRequiredForAction(action, credential)) {
      this.removeCredentialForAction(action, credential);
    } else {
      this.addCredentialForAction(action, credential);
    }
  }

  removeCredentialForAction(action, credential) {
    _.pull(this.content.desktopPrivileges[action], credential);
  }

  addCredentialForAction(action, credential) {
    const credentials = this.getCredentialsForAction(action);
    credentials.push(credential);
    this.setCredentialsForAction(action, credentials);
  }

  isCredentialRequiredForAction(action, credential) {
    const credentialsRequired = this.getCredentialsForAction(action);
    return credentialsRequired.includes(credential);
  }
}
