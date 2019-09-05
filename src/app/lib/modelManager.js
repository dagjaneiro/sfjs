import _ from 'lodash';
import { SFJS } from '../../standard_file';
import { SFItem } from '../models/item';
import { SFItemParams } from '../models/itemParams';

export class SFModelManager {
  constructor(timeout) {
    this.$timeout = timeout || setTimeout.bind(window);

    this.itemSyncObservers = [];
    this.items = [];
    this.itemsHash = {};
    this.missedReferences = {};
    this.uuidChangeObservers = [];
  }

  handleSignout() {
    this.items.length = 0;
    this.itemsHash = {};
    this.missedReferences = {};
  }

  addModelUuidChangeObserver(id, callback) {
    this.uuidChangeObservers.push({ id: id, callback: callback });
  }

  notifyObserversOfUuidChange(oldItem, newItem) {
    for (const observer of this.uuidChangeObservers) {
      try {
        observer.callback(oldItem, newItem);
      } catch (e) {
        console.error('Notify observers of uuid change exception:', e);
      }
    }
  }

  async alternateUUIDForItem(item) {
    // We need to clone this item and give it a new uuid, then delete item with old uuid from db (you can't modify uuid's in our indexeddb setup)
    const newItem = this.createItem(item);
    newItem.uuid = await SFJS.crypto.generateUUID();

    // Update uuids of relationships
    newItem.informReferencesOfUUIDChange(item.uuid, newItem.uuid);
    this.informModelsOfUUIDChangeForItem(newItem, item.uuid, newItem.uuid);

    // the new item should inherit the original's relationships
    for (const referencingObject of item.referencingObjects) {
      referencingObject.setIsNoLongerBeingReferencedBy(item);
      item.setIsNoLongerBeingReferencedBy(referencingObject);
      referencingObject.addItemAsRelationship(newItem);
    }

    this.setItemsDirty(item.referencingObjects, true);

    // Used to set up referencingObjects for new item (so that other items can now properly reference this new item)
    this.resolveReferencesForItem(newItem);

    if (this.loggingEnabled) {
      console.log(item.uuid, '-->', newItem.uuid);
    }

    // Set to deleted, then run through mapping function so that observers can be notified
    item.deleted = true;
    item.content.references = [];
    // Don't set dirty, because we don't need to sync old item. alternating uuid only occurs in two cases:
    // signing in and merging offline data, or when a uuid-conflict occurs. In both cases, the original item never
    // saves to a server, so doesn't need to be synced.
    // informModelsOfUUIDChangeForItem may set this object to dirty, but we want to undo that here, so that the item gets deleted
    // right away through the mapping function.
    this.setItemDirty(
      item,
      false,
      false,
      SFModelManager.MappingSourceLocalSaved
    );
    await this.mapResponseItemsToLocalModels(
      [item],
      SFModelManager.MappingSourceLocalSaved
    );

    // add new item
    this.addItem(newItem);
    this.setItemDirty(
      newItem,
      true,
      true,
      SFModelManager.MappingSourceLocalSaved
    );

    this.notifyObserversOfUuidChange(item, newItem);

    return newItem;
  }

  informModelsOfUUIDChangeForItem(newItem, oldUUID, newUUID) {
    // some models that only have one-way relationships might be interested to hear that an item has changed its uuid
    // for example, editors have a one way relationship with notes. When a note changes its UUID, it has no way to inform the editor
    // to update its relationships

    for (const model of this.items) {
      model.potentialItemOfInterestHasChangedItsUUID(newItem, oldUUID, newUUID);
    }
  }

  didSyncModelsOffline(items) {
    this.notifySyncObserversOfModels(
      items,
      SFModelManager.MappingSourceLocalSaved
    );
  }

  async mapResponseItemsToLocalModels(items, source, sourceKey) {
    return this.mapResponseItemsToLocalModelsWithOptions({
      items,
      source,
      sourceKey
    });
  }

  async mapResponseItemsToLocalModelsOmittingFields(
    items,
    omitFields,
    source,
    sourceKey
  ) {
    return this.mapResponseItemsToLocalModelsWithOptions({
      items,
      omitFields,
      source,
      sourceKey
    });
  }

  async mapResponseItemsToLocalModelsWithOptions({
    items,
    omitFields,
    source,
    sourceKey,
    options
  }) {
    const models = [];
    const processedObjects = [];
    const modelsToNotifyObserversOf = [];

    // first loop should add and process items
    for (const json_obj of items) {
      if (!json_obj) {
        continue;
      }

      // content is missing if it has been sucessfullly decrypted but no content
      const isMissingContent = !json_obj.content && !json_obj.errorDecrypting;
      const isCorrupt = !json_obj.content_type || !json_obj.uuid;
      if ((isCorrupt || isMissingContent) && !json_obj.deleted) {
        // An item that is not deleted should never have empty content
        console.error('Server response item is corrupt:', json_obj);
        continue;
      }

      // Lodash's _.omit, which was previously used, seems to cause unexpected behavior
      // when json_obj is an ES6 item class. So we instead manually omit each key.
      if (Array.isArray(omitFields)) {
        for (const key of omitFields) {
          delete json_obj[key];
        }
      }

      let item = this.findItem(json_obj.uuid);

      if (item) {
        item.updateFromJSON(json_obj);
        // If an item goes through mapping, it can no longer be a dummy.
        item.dummy = false;
      }

      const contentType =
        json_obj['content_type'] || (item && item.content_type);
      const unknownContentType =
        this.acceptableContentTypes &&
        !this.acceptableContentTypes.includes(contentType);
      if (unknownContentType) {
        continue;
      }

      let isDirtyItemPendingDelete = false;
      if (json_obj.deleted === true) {
        if (json_obj.dirty) {
          // Item was marked as deleted but not yet synced (in offline scenario)
          // We need to create this item as usual, but just not add it to individual arrays
          // i.e add to this.items but not this.notes (so that it can be retrieved with getDirtyItems)
          isDirtyItemPendingDelete = true;
        } else {
          if (item) {
            // We still want to return this item to the caller so they know it was handled.
            models.push(item);

            modelsToNotifyObserversOf.push(item);
            this.removeItemLocally(item);
          }
          continue;
        }
      }

      if (!item) {
        item = this.createItem(json_obj);
      }

      this.addItem(item, isDirtyItemPendingDelete);

      // Observers do not need to handle items that errored while decrypting.
      if (!item.errorDecrypting) {
        modelsToNotifyObserversOf.push(item);
      }

      models.push(item);
      processedObjects.push(json_obj);
    }

    // second loop should process references
    for (const [index, json_obj] of processedObjects.entries()) {
      const model = models[index];
      if (json_obj.content) {
        this.resolveReferencesForItem(model);
      }

      model.didFinishSyncing();
    }

    const missedRefs = this.popMissedReferenceStructsForObjects(
      processedObjects
    );
    for (const ref of missedRefs) {
      const model = models.find(
        candidate => candidate.uuid === ref.reference_uuid
      );
      // Model should 100% be defined here, but let's not be too overconfident
      if (model) {
        const itemWaitingForTheValueInThisCurrentLoop = ref.for_item;
        itemWaitingForTheValueInThisCurrentLoop.addItemAsRelationship(model);
      }
    }

    await this.notifySyncObserversOfModels(
      modelsToNotifyObserversOf,
      source,
      sourceKey
    );

    return models;
  }

  missedReferenceBuildKey(referenceId, objectId) {
    return `${referenceId}:${objectId}`;
  }

  popMissedReferenceStructsForObjects(objects) {
    if (!objects || objects.length === 0) {
      return [];
    }

    const results = [];
    const toDelete = [];
    const uuids = objects.map(item => item.uuid);
    const genericUuidLength = uuids[0].length;

    const keys = Object.keys(this.missedReferences);
    for (const candidateKey of keys) {
      /*
      We used to do string.split to get at the UUID, but surprisingly,
      the performance of this was about 20x worse then just getting the substring.

      let matches = candidateKey.split(":")[0] == object.uuid;
      */
      const matches = uuids.includes(
        candidateKey.substring(0, genericUuidLength)
      );
      if (matches) {
        results.push(this.missedReferences[candidateKey]);
        toDelete.push(candidateKey);
      }
    }

    // remove from hash
    for (const key of toDelete) {
      delete this.missedReferences[key];
    }

    return results;
  }

  resolveReferencesForItem(item, markReferencesDirty = false) {
    if (item.errorDecrypting) {
      return;
    }

    const contentObject = item.contentObject;

    // If another client removes an item's references, this client won't pick up the removal unless
    // we remove everything not present in the current list of references
    item.updateLocalRelationships();

    if (!contentObject.references) {
      return;
    }

    const references = contentObject.references.slice(); // make copy, references will be modified in array

    const referencesIds = references.map(ref => {
      return ref.uuid;
    });
    const includeBlanks = true;
    const referencesObjectResults = this.findItems(
      referencesIds,
      includeBlanks
    );

    for (const [index, referencedItem] of referencesObjectResults.entries()) {
      if (referencedItem) {
        item.addItemAsRelationship(referencedItem);
        if (markReferencesDirty) {
          this.setItemDirty(referencedItem, true);
        }
      } else {
        const missingRefId = referencesIds[index];
        // Allows mapper to check when missing reference makes it through the loop,
        // and then runs resolveReferencesForItem again for the original item.
        const mappingKey = this.missedReferenceBuildKey(
          missingRefId,
          item.uuid
        );
        if (!this.missedReferences[mappingKey]) {
          const missedRef = { reference_uuid: missingRefId, for_item: item };
          this.missedReferences[mappingKey] = missedRef;
        }
      }
    }
  }

  /* Note that this function is public, and can also be called manually (desktopManager uses it) */
  async notifySyncObserversOfModels(models, source, sourceKey) {
    // Make sure `let` is used in the for loops instead of `var`, as we will be using a timeout below.
    const observers = this.itemSyncObservers.sort((a, b) => {
      // sort by priority
      return a.priority < b.priority ? -1 : 1;
    });
    for (const observer of observers) {
      const allRelevantItems = observer.types.includes('*')
        ? models
        : models.filter(item => {
            return observer.types.includes(item.content_type);
          });
      const validItems = [];
      const deletedItems = [];
      for (const item of allRelevantItems) {
        if (item.deleted) {
          deletedItems.push(item);
        } else {
          validItems.push(item);
        }
      }

      if (allRelevantItems.length > 0) {
        await this._callSyncObserverCallbackWithTimeout(
          observer,
          allRelevantItems,
          validItems,
          deletedItems,
          source,
          sourceKey
        );
      }
    }
  }

  /*
    Rather than running this inline in a for loop, which causes problems and requires all variables to be declared with `let`,
    we'll do it here so it's more explicit and less confusing.
   */
  async _callSyncObserverCallbackWithTimeout(
    observer,
    allRelevantItems,
    validItems,
    deletedItems,
    source,
    sourceKey
  ) {
    return new Promise((resolve, reject) => {
      this.$timeout(() => {
        try {
          observer.callback(
            allRelevantItems,
            validItems,
            deletedItems,
            source,
            sourceKey
          );
        } catch (e) {
          console.error('Sync observer exception', e);
        } finally {
          resolve();
        }
      });
    });
  }

  // When a client sets an item as dirty, it means its values has changed, and everyone should know about it.
  // Particularly extensions. For example, if you edit the title of a note, extensions won't be notified until the save sync completes.
  // With this, they'll be notified immediately.
  setItemDirty(item, dirty = true, updateClientDate, source, sourceKey) {
    this.setItemsDirty([item], dirty, updateClientDate, source, sourceKey);
  }

  setItemsDirty(items, dirty = true, updateClientDate, source, sourceKey) {
    for (const item of items) {
      item.setDirty(dirty, updateClientDate);
    }
    this.notifySyncObserversOfModels(
      items,
      source || SFModelManager.MappingSourceLocalDirtied,
      sourceKey
    );
  }

  createItem(json_obj) {
    let ItemClass =
      SFModelManager.ContentTypeClassMapping &&
      SFModelManager.ContentTypeClassMapping[json_obj.content_type];
    if (!ItemClass) {
      ItemClass = SFItem;
    }

    const item = new ItemClass(json_obj);
    return item;
  }

  /*
    Be sure itemResponse is a generic Javascript object, and not an Item.
    An Item needs to collapse its properties into its content object before it can be duplicated.
    Note: the reason we need this function is specificallty for the call to resolveReferencesForItem.
    This method creates but does not add the item to the global inventory. It's used by syncManager
    to check if this prospective duplicate item is identical to another item, including the references.
   */
  async createDuplicateItemFromResponseItem(itemResponse) {
    if (typeof itemResponse.setDirty === 'function') {
      // You should never pass in objects here, as we will modify the itemResponse's uuid below (update: we now make a copy of input value).
      console.error(
        'Attempting to create conflicted copy of non-response item.'
      );
      return null;
    }
    // Make a copy so we don't modify input value.
    const itemResponseCopy = JSON.parse(JSON.stringify(itemResponse));
    itemResponseCopy.uuid = await SFJS.crypto.generateUUID();
    const duplicate = this.createItem(itemResponseCopy);
    return duplicate;
  }

  duplicateItemAndAddAsConflict(duplicateOf) {
    return this.duplicateItemWithCustomContentAndAddAsConflict({
      content: duplicateOf.content,
      duplicateOf
    });
  }

  duplicateItemWithCustomContentAndAddAsConflict({ content, duplicateOf }) {
    const copy = this.duplicateItemWithCustomContent({ content, duplicateOf });
    this.addDuplicatedItemAsConflict({ duplicate: copy, duplicateOf });
    return copy;
  }

  addDuplicatedItemAsConflict({ duplicate, duplicateOf }) {
    this.addDuplicatedItem(duplicate, duplicateOf);
    duplicate.content.conflict_of = duplicateOf.uuid;
  }

  duplicateItemWithCustomContent({ content, duplicateOf }) {
    const copy = new duplicateOf.constructor({ content });
    copy.created_at = duplicateOf.created_at;
    if (!copy.content_type) {
      copy.content_type = duplicateOf.content_type;
    }
    return copy;
  }

  duplicateItemAndAdd(item) {
    const copy = this.duplicateItemWithoutAdding(item);
    this.addDuplicatedItem(copy, item);
    return copy;
  }

  duplicateItemWithoutAdding(item) {
    const copy = new item.constructor({ content: item.content });
    copy.created_at = item.created_at;
    if (!copy.content_type) {
      copy.content_type = item.content_type;
    }
    return copy;
  }

  addDuplicatedItem(duplicate, original) {
    this.addItem(duplicate);
    // the duplicate should inherit the original's relationships
    for (const referencingObject of original.referencingObjects) {
      referencingObject.addItemAsRelationship(duplicate);
      this.setItemDirty(referencingObject, true);
    }
    this.resolveReferencesForItem(duplicate);
    this.setItemDirty(duplicate, true);
  }

  addItem(item, globalOnly = false) {
    this.addItems([item], globalOnly);
  }

  addItems(items, globalOnly = false) {
    items.forEach(item => {
      if (!this.itemsHash[item.uuid]) {
        this.itemsHash[item.uuid] = item;
        this.items.push(item);
      }
    });
  }

  /* Notifies observers when an item has been synced or mapped from a remote response */
  addItemSyncObserver(id, types, callback) {
    this.addItemSyncObserverWithPriority({ id, types, callback, priority: 1 });
  }

  addItemSyncObserverWithPriority({ id, priority, types, callback }) {
    if (!Array.isArray(types)) {
      types = [types];
    }
    this.itemSyncObservers.push({ id, types, priority, callback });
  }

  removeItemSyncObserver(id) {
    _.remove(
      this.itemSyncObservers,
      _.find(this.itemSyncObservers, { id: id })
    );
  }

  getDirtyItems() {
    return this.items.filter(item => {
      // An item that has an error decrypting can be synced only if it is being deleted.
      // Otherwise, we don't want to send corrupt content up to the server.
      return (
        item.dirty === true &&
        !item.dummy &&
        (!item.errorDecrypting || item.deleted)
      );
    });
  }

  clearDirtyItems(items) {
    for (const item of items) {
      item.setDirty(false);
    }
  }

  removeAndDirtyAllRelationshipsForItem(item) {
    // Handle direct relationships
    // An item with errorDecrypting will not have valid content field
    if (!item.errorDecrypting) {
      for (const reference of item.content.references) {
        const relationship = this.findItem(reference.uuid);
        if (relationship) {
          item.removeItemAsRelationship(relationship);
          if (relationship.hasRelationshipWithItem(item)) {
            relationship.removeItemAsRelationship(item);
            this.setItemDirty(relationship, true);
          }
        }
      }
    }

    // Handle indirect relationships
    for (const object of item.referencingObjects) {
      object.removeItemAsRelationship(item);
      this.setItemDirty(object, true);
    }

    item.referencingObjects = [];
  }

  /* Used when changing encryption key */
  setAllItemsDirty() {
    const relevantItems = this.allItems;
    this.setItemsDirty(relevantItems, true);
  }

  setItemToBeDeleted(item) {
    item.deleted = true;

    if (!item.dummy) {
      this.setItemDirty(item, true);
    }

    this.removeAndDirtyAllRelationshipsForItem(item);
  }

  async removeItemLocally(item) {
    _.remove(this.items, { uuid: item.uuid });

    delete this.itemsHash[item.uuid];

    item.isBeingRemovedLocally();
  }

  /* Searching */

  get allItems() {
    return this.items.slice();
  }

  get allNondummyItems() {
    return this.items.filter(function(item) {
      return !item.dummy;
    });
  }

  allItemsMatchingTypes(contentTypes) {
    return this.allItems.filter(function(item) {
      return (
        (_.includes(contentTypes, item.content_type) ||
          _.includes(contentTypes, '*')) &&
        !item.dummy
      );
    });
  }

  invalidItems() {
    return this.allItems.filter(item => {
      return item.errorDecrypting;
    });
  }

  validItemsForContentType(contentType) {
    return this.allItems.filter(item => {
      return item.content_type === contentType && !item.errorDecrypting;
    });
  }

  findItem(itemId) {
    return this.itemsHash[itemId];
  }

  findItems(ids, includeBlanks = false) {
    const results = [];
    for (const id of ids) {
      const item = this.itemsHash[id];
      if (item || includeBlanks) {
        results.push(item);
      }
    }
    return results;
  }

  itemsMatchingPredicate(predicate) {
    return this.itemsMatchingPredicates([predicate]);
  }

  itemsMatchingPredicates(predicates) {
    return this.filterItemsWithPredicates(this.allItems, predicates);
  }

  filterItemsWithPredicates(items, predicates) {
    const results = items.filter(item => {
      for (const predicate of predicates) {
        if (!item.satisfiesPredicate(predicate)) {
          return false;
        }
      }
      return true;
    });

    return results;
  }

  /*
  Archives
  */

  async importItems(externalItems) {
    const itemsToBeMapped = [];
    // Get local values before doing any processing. This way, if a note change below modifies a tag,
    // and the tag is going to be iterated on in the same loop, then we don't want this change to be compared
    // to the local value.
    const localValues = {};
    for (const itemData of externalItems) {
      const localItem = this.findItem(itemData.uuid);
      if (!localItem) {
        localValues[itemData.uuid] = {};
        continue;
      }
      const frozenValue = this.duplicateItemWithoutAdding(localItem);
      localValues[itemData.uuid] = { frozenValue, itemRef: localItem };
    }

    for (const itemData of externalItems) {
      const { frozenValue, itemRef } = localValues[itemData.uuid];
      if (frozenValue && !itemRef.errorDecrypting) {
        // if the item already exists, check to see if it's different from the import data.
        // If it's the same, do nothing, otherwise, create a copy.
        const duplicate = await this.createDuplicateItemFromResponseItem(
          itemData
        );
        if (
          !itemData.deleted &&
          !frozenValue.isItemContentEqualWith(duplicate)
        ) {
          // Data differs
          this.addDuplicatedItemAsConflict({ duplicate, duplicateOf: itemRef });
          itemsToBeMapped.push(duplicate);
        }
      } else {
        // it doesn't exist, push it into items to be mapped
        itemsToBeMapped.push(itemData);
        if (itemRef && itemRef.errorDecrypting) {
          itemRef.errorDecrypting = false;
        }
      }
    }

    const items = await this.mapResponseItemsToLocalModels(
      itemsToBeMapped,
      SFModelManager.MappingSourceFileImport
    );
    for (const item of items) {
      this.setItemDirty(item, true, false);
      item.deleted = false;
    }

    return items;
  }

  async getAllItemsJSONData(keys, authParams, returnNullIfEmpty) {
    return this.getJSONDataForItems(
      this.allItems,
      keys,
      authParams,
      returnNullIfEmpty
    );
  }

  async getJSONDataForItems(items, keys, authParams, returnNullIfEmpty) {
    return Promise.all(
      items.map(item => {
        const itemParams = new SFItemParams(item, keys, authParams);
        return itemParams.paramsForExportFile();
      })
    ).then(items => {
      if (returnNullIfEmpty && items.length === 0) {
        return null;
      }

      const data = { items: items };

      if (keys) {
        // auth params are only needed when encrypted with a standard file key
        data['auth_params'] = authParams;
      }

      return JSON.stringify(data, null, 2 /* pretty print */);
    });
  }

  async computeDataIntegrityHash() {
    try {
      const items = this.allNondummyItems.sort((a, b) => {
        return b.updated_at - a.updated_at;
      });
      const dates = items.map(item => item.updatedAtTimestamp());
      const string = dates.join(',');
      const hash = await SFJS.crypto.sha256(string);
      return hash;
    } catch (e) {
      console.error('Error computing data integrity hash', e);
      return null;
    }
  }
}

SFModelManager.MappingSourceRemoteRetrieved = 'MappingSourceRemoteRetrieved';
SFModelManager.MappingSourceRemoteSaved = 'MappingSourceRemoteSaved';
SFModelManager.MappingSourceLocalSaved = 'MappingSourceLocalSaved';
SFModelManager.MappingSourceLocalRetrieved = 'MappingSourceLocalRetrieved';
SFModelManager.MappingSourceLocalDirtied = 'MappingSourceLocalDirtied';
SFModelManager.MappingSourceComponentRetrieved =
  'MappingSourceComponentRetrieved';
SFModelManager.MappingSourceDesktopInstalled = 'MappingSourceDesktopInstalled'; // When a component is installed by the desktop and some of its values change
SFModelManager.MappingSourceRemoteActionRetrieved =
  'MappingSourceRemoteActionRetrieved'; /* aciton-based Extensions like note history */
SFModelManager.MappingSourceFileImport = 'MappingSourceFileImport';

SFModelManager.isMappingSourceRetrieved = source => {
  return [
    SFModelManager.MappingSourceRemoteRetrieved,
    SFModelManager.MappingSourceComponentRetrieved,
    SFModelManager.MappingSourceRemoteActionRetrieved
  ].includes(source);
};
