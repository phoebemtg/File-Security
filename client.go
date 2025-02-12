package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// Type definition for the User struct.
type User struct {
	Username  string
	DSSignKey userlib.DSSignKey
	PKEDecKey userlib.PKEDecKey
	encKey    []byte
	macKey    []byte
}

// Files will be stored as a linked list
type ContentNode struct {
	Contents uuid.UUID
	NextNode uuid.UUID
}

// Simplifies file appending, can hop straight to last node
type FileHead struct {
	FirstNode uuid.UUID
	LastNode  uuid.UUID
}

// Sharing permissions will be stored as a tree
type FileNode struct {
	Username      string
	Filename      string
	FileHead      uuid.UUID
	Children      []uuid.UUID
	ChildrenNames []string
}

// Simple struct to hold all info needed for an invitation
type Invitation struct {
	Owner      string
	ParentNode uuid.UUID
	FileKey    []byte
}

// UUID's are made with common scheme, i.e. "structs" + username
func getUUID(query string, username string) (userID uuid.UUID) {
	queryHash := userlib.Hash([]byte(query))[:8]
	userHash := userlib.Hash([]byte(username))[:8]
	result, _ := uuid.FromBytes(append(queryHash, userHash...))
	return result
}

// Helper function to encrypt content, tag, then store in datastore with symmetric scheme
func symEncThenTag(encKey []byte, macKey []byte, content interface{}, id uuid.UUID) (err error) {
	marshalContent, err := json.Marshal(content)
	if err != nil {
		return err
	}

	iv := userlib.RandomBytes(16)
	encContent := userlib.SymEnc(encKey[:16], iv, marshalContent)

	tag, err := userlib.HMACEval(macKey[:16], encContent)
	if err != nil {
		return err
	}

	taggedStruct := append(tag, encContent...)
	userlib.DatastoreSet(id, taggedStruct)

	return nil
}

// Helper function to verify datastore entry then decrypt with symmetric scheme
func symVerifyThenDec(encKey []byte, macKey []byte, id uuid.UUID) (content []byte, err error) {
	dataStoreEntry, ok := userlib.DatastoreGet(id)
	if !ok {
		return content, errors.New("datastore entry at Id does not exist")
	}

	if len(dataStoreEntry) < 64 {
		return content, errors.New("tampering has occurred")
	}

	tag := dataStoreEntry[:64]
	encMarshalContent := dataStoreEntry[64:]

	newTag, err := userlib.HMACEval(macKey[:16], encMarshalContent)
	if err != nil {
		return content, err
	}

	tagCheck := userlib.HMACEqual(tag, newTag)
	if !tagCheck {
		return content, errors.New("tags are not equal, content has been changed")
	}

	content = userlib.SymDec(encKey[:16], encMarshalContent)

	return content, nil
}

// Helper function to encrypt content, tag, then store in datastore with asymmetric scheme
func asymEncThenTag(username string, signKey userlib.DSSignKey, content interface{}, id uuid.UUID) (err error) {
	keyId := getUUID("pke", username)
	encKey, ok := userlib.KeystoreGet(keyId.String())
	if !ok {
		return errors.New("could not find user's PKEEncKey in keystore")
	}

	marshalContent, err := json.Marshal(content)
	if err != nil {
		return err
	}

	encContent, err := userlib.PKEEnc(encKey, marshalContent)
	if err != nil {
		return err
	}

	tag, err := userlib.DSSign(signKey, encContent)
	if err != nil {
		return err
	}

	taggedStruct := append(tag, encContent...)
	userlib.DatastoreSet(id, taggedStruct)

	return nil
}

// Helper function to verify datastore entry then decrypt with asymmetric scheme
func asymVerifyThenDec(username string, decKey userlib.PKEDecKey, id uuid.UUID) (content []byte, err error) {
	sigId := getUUID("ds", username)
	verifyKey, ok := userlib.KeystoreGet(sigId.String())
	if !ok {
		return content, errors.New("could not find user's DSVerifyKey in keystore")
	}

	dataStoreEntry, ok := userlib.DatastoreGet(id)
	if !ok {
		return content, errors.New("datastore entry at Id does not exist")
	}

	if len(dataStoreEntry) < 256 {
		return content, errors.New("tampering has occurred")
	}

	sig := dataStoreEntry[:256]
	encMarshalContent := dataStoreEntry[256:]

	err = userlib.DSVerify(verifyKey, encMarshalContent, sig)
	if err != nil {
		return content, err
	}

	content, err = userlib.PKEDec(decKey, encMarshalContent)
	if err != nil {
		return content, err
	}

	return content, nil
}

// Get file keys from datastore (may need to verify with owner's DS key)
func getFileKeys(user *User, filename string) (fileKey []byte, fileMacKey []byte, err error) {
	// Verify then decrypt file key from datastore
	keyId := getUUID(filename+"key", user.Username)
	fileKeyEntry, err := symVerifyThenDec(user.encKey, user.macKey, keyId)
	// If erroring, may be because owner has overwritten file key after it changed.
	if err != nil {
		ownerId := getUUID(filename+"owner", user.Username)
		ownerEntry, err := symVerifyThenDec(user.encKey, user.macKey, ownerId)
		if err != nil {
			return fileKey, fileMacKey, err
		}
		var ownerName string
		err = json.Unmarshal(ownerEntry, &ownerName)
		if err != nil {
			return fileKey, fileMacKey, err
		}

		fileKeyEntry, err = asymVerifyThenDec(ownerName, user.PKEDecKey, keyId)
		if err != nil {
			return fileKey, fileMacKey, err
		}
	}

	err = json.Unmarshal(fileKeyEntry, &fileKey)
	if err != nil {
		return fileKey, fileMacKey, err
	}
	fileMacKey, err = userlib.HashKDF(fileKey, []byte("mac-key"))
	if err != nil {
		return fileKey, fileMacKey, err
	}
	return fileKey, fileMacKey, nil
}

func getFileHead(fileKey []byte, fileMacKey []byte, filename string, username string) (fileHead FileHead, fileHeadId uuid.UUID, err error) {
	// Verify then decrypt file node
	fileNodeId := getUUID(filename, username)
	fileNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, fileNodeId)
	if err != nil {
		return fileHead, fileHeadId, err
	}
	var fileNode FileNode
	err = json.Unmarshal(fileNodeEntry, &fileNode)
	if err != nil {
		return fileHead, fileHeadId, err
	}

	// Verify then decrypt file head
	fileHeadEntry, err := symVerifyThenDec(fileKey, fileMacKey, fileNode.FileHead)
	if err != nil {
		return fileHead, fileHeadId, err
	}
	err = json.Unmarshal(fileHeadEntry, &fileHead)
	if err != nil {
		return fileHead, fileHeadId, err
	}

	return fileHead, fileNode.FileHead, nil
}

func cleanFileTree(fileKey []byte, newFileKey []byte, fileNodeId uuid.UUID, head uuid.UUID, sign userlib.DSSignKey) (err error) {
	// Derive MAC keys
	fileMacKey, err := userlib.HashKDF(fileKey, []byte("mac-key"))
	if err != nil {
		return err
	}
	newFileMacKey, err := userlib.HashKDF(newFileKey, []byte("mac-key"))
	if err != nil {
		return err
	}

	// Get file node
	fileNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, fileNodeId)
	if err != nil {
		return err
	}
	var fileNode FileNode
	err = json.Unmarshal(fileNodeEntry, &fileNode)
	if err != nil {
		return err
	}

	newChildren := fileNode.Children
	for _, id := range fileNode.Children {
		// Verify then decrypt child file node
		childFileNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, id)
		if err != nil {
			return err
		}
		var childFileNode FileNode
		err = json.Unmarshal(childFileNodeEntry, &childFileNode)
		if err != nil {
			return err
		}

		cleanFileTree(fileKey, newFileKey, id, head, sign)
	}
	// Update values for file node
	fileNode.Children = newChildren
	fileNode.FileHead = head
	err = symEncThenTag(newFileKey, newFileMacKey, fileNode, fileNodeId)
	if err != nil {
		return err
	}

	// Store new file key for current user
	fileKeyId := getUUID(fileNode.Filename+"key", fileNode.Username)
	err = asymEncThenTag(fileNode.Username, sign, newFileKey, fileKeyId)
	if err != nil {
		return err
	}

	return nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return userdataptr, errors.New("invalid username")
	}

	var userdata User
	userdata.Username = username

	// Get sign and verify keys for digital signatures
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return &userdata, err
	}

	// Add sign key to struct, verify key to Keystore
	userdata.DSSignKey = DSSignKey
	id := getUUID("ds", username)
	err = userlib.KeystoreSet(id.String(), DSVerifyKey)
	if err != nil {
		return &userdata, err
	}

	// Get public and private keys for enc/dec
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return &userdata, err
	}

	// Add public key to keystore, private key to struct
	userdata.PKEDecKey = PKEDecKey
	id = getUUID("pke", username)
	err = userlib.KeystoreSet(id.String(), PKEEncKey)
	if err != nil {
		return &userdata, err
	}

	// Generate root key using salt and password
	salt := userlib.RandomBytes(32)
	rootKey := userlib.Argon2Key([]byte(password), salt, 16)

	// Derive encryption/authentication keys
	encKey, err := userlib.HashKDF(rootKey, []byte("enc-key"))
	if err != nil {
		return &userdata, err
	}
	macKey, err := userlib.HashKDF(rootKey, []byte("mac-key"))
	if err != nil {
		return &userdata, err
	}

	// Store salt in datastore
	id = getUUID("salt", username)
	userlib.DatastoreSet(id, salt)

	// Tag user struct and store in datastore
	id = getUUID("struct", username)
	err = symEncThenTag(encKey, macKey, userdata, id)
	if err != nil {
		return &userdata, err
	}

	// Add derived keys to user struct
	userdata.encKey = encKey
	userdata.macKey = macKey

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Get user's salt from datastore
	id := getUUID("salt", username)
	salt, ok := userlib.DatastoreGet(id)
	if !ok {
		return &userdata, errors.New("user salt doesn't exist")
	}

	// Get user's struct from datastore
	id = getUUID("struct", username)

	// Get root key and derive enc/mac keys
	rootKey := userlib.Argon2Key([]byte(password), salt, 16)

	encKey, err := userlib.HashKDF(rootKey, []byte("enc-key"))
	if err != nil {
		return &userdata, err
	}
	macKey, err := userlib.HashKDF(rootKey, []byte("mac-key"))
	if err != nil {
		return &userdata, err
	}

	// Verify/decrypt user struct then cast to User
	userdataEntry, err := symVerifyThenDec(encKey, macKey, id)
	if err != nil {
		return &userdata, err
	}
	err = json.Unmarshal(userdataEntry, userdataptr)
	if err != nil {
		return &userdata, err
	}

	// Add derived keys to user struct
	userdata.encKey = encKey
	userdata.macKey = macKey

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Get file node from datastore
	fileNodeId := getUUID(filename, userdata.Username)
	_, ok := userlib.DatastoreGet(fileNodeId)

	// If filenode exists, overwrite. o.w make new file
	if !ok {
		// Initialize file structure
		var fileNode FileNode
		fileNode.Username = userdata.Username
		fileNode.Filename = filename
		fileNode.Children = nil
		fileNode.FileHead = uuid.New()

		var fileHead FileHead
		contentNodeId := uuid.New()
		fileHead.FirstNode = contentNodeId
		fileHead.LastNode = contentNodeId

		var contentNode ContentNode
		contentNode.Contents = uuid.New()
		contentNode.NextNode = uuid.Nil

		// Generate File Key and File Mac Key
		fileKey := userlib.RandomBytes(16)
		fileMacKey, err := userlib.HashKDF(fileKey, []byte("mac-key"))
		if err != nil {
			return err
		}

		// Encrypt contents and store in datastore
		err = symEncThenTag(fileKey, fileMacKey, content, contentNode.Contents)
		if err != nil {
			return err
		}
		err = symEncThenTag(fileKey, fileMacKey, contentNode, contentNodeId)
		if err != nil {
			return err
		}
		err = symEncThenTag(fileKey, fileMacKey, fileHead, fileNode.FileHead)
		if err != nil {
			return err
		}
		err = symEncThenTag(fileKey, fileMacKey, fileNode, fileNodeId)
		if err != nil {
			return err
		}

		// Store file key in datastore under getUUID(filename + "key", username)
		fileKeyId := getUUID(filename+"key", userdata.Username)
		err = symEncThenTag(userdata.encKey, userdata.macKey, fileKey, fileKeyId)
		if err != nil {
			return err
		}

		// Store username since current user is file owner
		ownerId := getUUID(filename+"owner", userdata.Username)
		err = symEncThenTag(userdata.encKey, userdata.macKey, userdata.Username, ownerId)
		if err != nil {
			return err
		}
	} else {
		// Get file key and file MAC key
		fileKey, fileMacKey, err := getFileKeys(userdata, filename)
		if err != nil {
			return err
		}

		// Get fileHead struct
		fileHead, fileHeadId, err := getFileHead(fileKey, fileMacKey, filename, userdata.Username)
		if err != nil {
			return err
		}

		// Verify then decrypt first content node
		contentNodeId := fileHead.FirstNode
		contentNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNodeId)
		if err != nil {
			return err
		}
		var contentNode ContentNode
		err = json.Unmarshal(contentNodeEntry, &contentNode)
		if err != nil {
			return err
		}

		// Recursively delete content nodes in linked list
		var nextNode ContentNode
		for contentNode.NextNode != uuid.Nil {
			// Verify then decrypt next node
			nextNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNode.NextNode)
			if err != nil {
				return err
			}
			err = json.Unmarshal(nextNodeEntry, &nextNode)
			if err != nil {
				return err
			}

			// Delete current node then update contentNode
			userlib.DatastoreDelete(contentNode.Contents)
			userlib.DatastoreDelete(contentNodeId)
			contentNodeId = contentNode.NextNode
			contentNode = nextNode
		}

		// Create new content node and clean up
		newContentNodeId := uuid.New()
		fileHead.FirstNode = newContentNodeId
		fileHead.LastNode = newContentNodeId

		var newContentNode ContentNode
		newContentNode.Contents = uuid.New()
		newContentNode.NextNode = uuid.Nil

		err = symEncThenTag(fileKey, fileMacKey, content, newContentNode.Contents)
		if err != nil {
			return err
		}

		err = symEncThenTag(fileKey, fileMacKey, newContentNode, newContentNodeId)
		if err != nil {
			return err
		}

		err = symEncThenTag(fileKey, fileMacKey, fileHead, fileHeadId)
		if err != nil {
			return err
		}
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Get the file keys
	fileKey, fileMacKey, err := getFileKeys(userdata, filename)
	if err != nil {
		return err
	}

	// Create new content node and store contents
	var contentNode ContentNode
	contentNode.NextNode = uuid.Nil
	contentNodeId := uuid.New()

	contentId := uuid.New()
	contentNode.Contents = contentId

	err = symEncThenTag(fileKey, fileMacKey, content, contentId)
	if err != nil {
		return err
	}

	err = symEncThenTag(fileKey, fileMacKey, contentNode, contentNodeId)
	if err != nil {
		return err
	}

	// Get fileHead struct and its UUID
	fileHead, fileHeadId, err := getFileHead(fileKey, fileMacKey, filename, userdata.Username)
	if err != nil {
		return err
	}

	// Add contentNode to list
	var lastNode ContentNode
	lastNodeId := fileHead.LastNode
	lastNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, lastNodeId)
	if err != nil {
		return err
	}
	err = json.Unmarshal(lastNodeEntry, &lastNode)
	if err != nil {
		return err
	}
	lastNode.NextNode = contentNodeId
	fileHead.LastNode = contentNodeId

	// Encrypt and store fileHead and previous ContentNode in list
	err = symEncThenTag(fileKey, fileMacKey, lastNode, lastNodeId)
	if err != nil {
		return err
	}

	err = symEncThenTag(fileKey, fileMacKey, fileHead, fileHeadId)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Get the file keys
	fileKey, fileMacKey, err := getFileKeys(userdata, filename)
	if err != nil {
		return content, err
	}

	// Get fileHead struct and its UUID
	fileHead, _, err := getFileHead(fileKey, fileMacKey, filename, userdata.Username)
	if err != nil {
		return content, err
	}

	// Verify then decrypt first content node
	contentNodeId := fileHead.FirstNode
	contentNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNodeId)
	if err != nil {
		return content, err
	}
	var contentNode ContentNode
	err = json.Unmarshal(contentNodeEntry, &contentNode)
	if err != nil {
		return content, err
	}

	// Get contents of first node and add to content
	contentEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNode.Contents)
	if err != nil {
		return content, err
	}
	var contentBytes []byte
	err = json.Unmarshal(contentEntry, &contentBytes)
	if err != nil {
		return content, err
	}
	content = contentBytes

	// Recursively add content from nodes in linked list
	for contentNode.NextNode != uuid.Nil {
		// Verify then decrypt next node
		contentNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNode.NextNode)
		if err != nil {
			return content, err
		}
		err = json.Unmarshal(contentNodeEntry, &contentNode)
		if err != nil {
			return content, err
		}

		// Verify then decrypt content
		contentEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNode.Contents)
		if err != nil {
			return content, err
		}
		err = json.Unmarshal(contentEntry, &contentBytes)
		if err != nil {
			return content, err
		}

		// Append to content and iterate down list
		content = append(content, contentBytes...)
	}

	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Retrieve ownername, file key, and file node id
	ownerId := getUUID(filename+"owner", userdata.Username)
	ownerNameEntry, err := symVerifyThenDec(userdata.encKey, userdata.macKey, ownerId)
	if err != nil {
		return invitationPtr, err
	}
	var ownerName string
	err = json.Unmarshal(ownerNameEntry, &ownerName)
	if err != nil {
		return invitationPtr, err
	}

	fileKey, fileMacKey, err := getFileKeys(userdata, filename)
	if err != nil {
		return invitationPtr, err
	}

	// Verify file actually exists in datastore
	_, _, err = getFileHead(fileKey, fileMacKey, filename, userdata.Username)
	if err != nil {
		return invitationPtr, err
	}

	// Create invitation struct and store in datastore
	var invitation Invitation
	invitation.Owner = ownerName
	invitation.FileKey = fileKey
	invitation.ParentNode = getUUID(filename, userdata.Username)

	invitationPtr = uuid.New()
	err = asymEncThenTag(recipientUsername, userdata.DSSignKey, invitation, invitationPtr)
	if err != nil {
		return invitationPtr, err
	}

	// Add new child name to file node
	fileNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, invitation.ParentNode)
	if err != nil {
		return invitationPtr, err
	}
	var fileNode FileNode
	err = json.Unmarshal(fileNodeEntry, &fileNode)
	if err != nil {
		return invitationPtr, err
	}
	fileNode.ChildrenNames = append(fileNode.ChildrenNames, recipientUsername)
	err = symEncThenTag(fileKey, fileMacKey, fileNode, invitation.ParentNode)
	if err != nil {
		return invitationPtr, err
	}

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Check if file already exists
	_, _, err := getFileKeys(userdata, filename)
	if err == nil {
		return errors.New("filename already exists in namespace")
	}

	// Retrieve and decrypt invitation
	invitationEntry, err := asymVerifyThenDec(senderUsername, userdata.PKEDecKey, invitationPtr)
	if err != nil {
		return err
	}
	var invitation Invitation
	err = json.Unmarshal(invitationEntry, &invitation)
	if err != nil {
		return err
	}

	fileKey := invitation.FileKey
	fileMacKey, err := userlib.HashKDF(fileKey, []byte("mac-key"))
	if err != nil {
		return err
	}

	// Get parent node
	parentFileNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, invitation.ParentNode)
	if err != nil {
		return err
	}
	var parentFileNode FileNode
	err = json.Unmarshal(parentFileNodeEntry, &parentFileNode)
	if err != nil {
		return err
	}

	// Create filenode struct
	var fileNode FileNode
	fileNode.Username = userdata.Username
	fileNode.Filename = filename
	fileNode.Children = nil
	fileNode.FileHead = parentFileNode.FileHead

	// Store new file node in datastore
	fileNodeId := getUUID(filename, userdata.Username)
	err = symEncThenTag(fileKey, fileMacKey, fileNode, fileNodeId)
	if err != nil {
		return err
	}

	// Add new file node to tree
	parentFileNode.Children = append(parentFileNode.Children, fileNodeId)
	err = symEncThenTag(fileKey, fileMacKey, parentFileNode, invitation.ParentNode)
	if err != nil {
		return err
	}

	// Store file key in datastore under getUUID(filename+"key", username)
	fileKeyId := getUUID(filename+"key", userdata.Username)
	err = symEncThenTag(userdata.encKey, userdata.macKey, fileKey, fileKeyId)
	if err != nil {
		return err
	}

	// Store file owner's name in datastore for future verification
	ownerId := getUUID(filename+"owner", userdata.Username)
	err = symEncThenTag(userdata.encKey, userdata.macKey, invitation.Owner, ownerId)
	if err != nil {
		return err
	}

	// Delete invitation from datastore
	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Make a new file key
	newFileKey := userlib.RandomBytes(16)
	newFileMacKey, err := userlib.HashKDF(newFileKey, []byte("mac-key"))
	if err != nil {
		return err
	}

	// Get the old file keys
	fileKey, fileMacKey, err := getFileKeys(userdata, filename)
	if err != nil {
		return err
	}

	// Get file node
	fileNodeId := getUUID(filename, userdata.Username)
	fileNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, fileNodeId)
	if err != nil {
		return err
	}
	var fileNode FileNode
	err = json.Unmarshal(fileNodeEntry, &fileNode)
	if err != nil {
		return err
	}

	// Remove recipient from shared users list
	newChildrenNames := fileNode.ChildrenNames
	for i, name := range fileNode.ChildrenNames {
		if name == recipientUsername {
			newChildrenNames = append(fileNode.ChildrenNames[:i], fileNode.ChildrenNames[i+1:]...)
		}
	}
	if len(newChildrenNames) == len(fileNode.ChildrenNames) {
		return errors.New("recipient was not shared with")
	}

	// Remove recipient from tree
	newChildren := fileNode.Children
	for i, id := range fileNode.Children {
		// Verify then decrypt child file node
		childFileNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, id)
		if err != nil {
			return err
		}
		var childFileNode FileNode
		err = json.Unmarshal(childFileNodeEntry, &childFileNode)
		if err != nil {
			return err
		}

		if childFileNode.Username == recipientUsername {
			newChildren = append(fileNode.Children[:i], fileNode.Children[i+1:]...)
		}
	}
	fileNode.Children = newChildren
	err = symEncThenTag(fileKey, fileMacKey, fileNode, fileNodeId)
	if err != nil {
		return err
	}

	// Get fileHead struct
	fileHead, fileHeadId, err := getFileHead(fileKey, fileMacKey, filename, userdata.Username)
	if err != nil {
		return err
	}

	// Verify then decrypt first content node
	contentNodeId := fileHead.FirstNode
	contentNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNodeId)
	if err != nil {
		return err
	}
	var contentNode ContentNode
	err = json.Unmarshal(contentNodeEntry, &contentNode)
	if err != nil {
		return err
	}

	// Setup new file head and start of content node chain
	var newFileHead FileHead
	newFileHeadId := uuid.New()
	newFileHead.FirstNode = uuid.New()

	var newContentNode ContentNode
	newContentNode.Contents = uuid.New()
	newContentNode.NextNode = uuid.New()

	// Recursively delete content nodes in linked list while copying to new list
	var nextNode ContentNode
	var content []byte
	newContentNodeId := newFileHead.FirstNode
	for contentNode.NextNode != uuid.Nil {
		// Get content from old content node then store in new one
		contentEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNode.Contents)
		if err != nil {
			return err
		}
		err = json.Unmarshal(contentEntry, &content)
		if err != nil {
			return err
		}
		err = symEncThenTag(newFileKey, newFileMacKey, content, newContentNode.Contents)
		if err != nil {
			return err
		}

		// Encrypt then tag new content node
		err = symEncThenTag(newFileKey, newFileMacKey, newContentNode, newContentNodeId)
		if err != nil {
			return err
		}

		// Update vars for next iteration
		newContentNodeId = newContentNode.NextNode
		newContentNode.Contents = uuid.New()
		newContentNode.NextNode = uuid.New()

		// Verify then decrypt next node in old chain
		nextNodeEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNode.NextNode)
		if err != nil {
			return err
		}
		err = json.Unmarshal(nextNodeEntry, &nextNode)
		if err != nil {
			return err
		}

		// Delete current node then update contentNode
		userlib.DatastoreDelete(contentNode.Contents)
		userlib.DatastoreDelete(contentNodeId)
		contentNodeId = contentNode.NextNode
		contentNode = nextNode
	}

	// Get content from old content node then store in new one
	contentEntry, err := symVerifyThenDec(fileKey, fileMacKey, contentNode.Contents)
	if err != nil {
		return err
	}
	err = json.Unmarshal(contentEntry, &content)
	if err != nil {
		return err
	}
	err = symEncThenTag(newFileKey, newFileMacKey, content, newContentNode.Contents)
	if err != nil {
		return err
	}

	// Encrypt then tag new content node
	err = symEncThenTag(newFileKey, newFileMacKey, newContentNode, newContentNodeId)
	if err != nil {
		return err
	}

	// Encrypt then tag last new content node
	newContentNode.NextNode = uuid.Nil
	err = symEncThenTag(newFileKey, newFileMacKey, newContentNode, newContentNodeId)
	if err != nil {
		return err
	}

	// Encrypt then tag new file head, delete old one
	newFileHead.LastNode = newContentNodeId
	err = symEncThenTag(newFileKey, newFileMacKey, newFileHead, newFileHeadId)
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(fileHeadId)

	// Remove all revoked users from file tree and give others the new file head
	err = cleanFileTree(fileKey, newFileKey, fileNodeId, newFileHeadId, userdata.DSSignKey)
	if err != nil {
		return err
	}

	return nil
}
