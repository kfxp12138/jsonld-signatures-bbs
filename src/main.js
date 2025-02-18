const { Bls12381G2KeyPair, BbsBlsSignature2020, BbsBlsSignatureProof2020, deriveProof} = require("./signature/index");
const { extendContextLoader, sign, verify, purposes } = require("jsonld-signatures")
const { createInputDocument, createControllerDoc, createIssuerKey, createVocab } = require("./tool")


async function createTemplate(items, issuerId, publicKeyId, templateName) {
  var publicKeyId = issuerId + '#' + publicKeyId
  var keyPairOptions = await createIssuerKey(publicKeyId, issuerId)
  var exampleControllerDoc = createControllerDoc(require("../data/controllerDocument.json"), issuerId, publicKeyId)
  var bbsContext = require("../data/bbs.json");
  var vocabUrl = "https://w3id.org/test/" + Math.round(Math.random() * 100000) + "/" + templateName
  var vocab = createVocab(require("../data/vocab.json"), templateName, items, vocabUrl)
  var credentialContext = require("../data/credentialsContext.json")
  var suiteContext = require("../data/suiteContext.json")
  documents = {
    "https://w3id.org/security/bbs/v1": bbsContext,
    "https://www.w3.org/2018/credentials/v1": credentialContext,
    "https://w3id.org/security/suites/jws-2020/v1": suiteContext,
  }
  documents[issuerId] = exampleControllerDoc
  documents[publicKeyId] = keyPairOptions
  documents[vocabUrl] = vocab
  return {
    "documents": documents,
    "vocabUrl": vocabUrl,
    "templateName": templateName,
    "issuerId": issuerId,
    "publicKeyId": publicKeyId
  }
  //在公开出去之前 需要将keyPairOptions.privateKeyBase58置空
}

function getVocabFromTemplate(template) {
  var vocabUrl = template["vocabUrl"]
  var templateName = template["templateName"]
  var documents = template["documents"]
  var items = documents[vocabUrl]['@context'][templateName]["@context"]
  var ignoreItems = ["@version", "@protected", "type", "test", "schema", "xsd"]
  var result = {}
  for (var item in items) {
    if (ignoreItems.indexOf(item) >= 0)
      continue
    else {
      result[item] = items[item]
    }
  }
  result.id = { '@id': 'test:id', '@type': 'xsd:string' }
  return result
}

function createInputDoc(template, attributes) {
  var vocabUrl = template.vocabUrl
  var templateName = template.templateName
  var issuerId = template.issuerId
  return createInputDocument(vocabUrl, templateName, issuerId, attributes)
}

function createRevealDoc(template,revealedAttributes){
  deriveDoc=require("../data/deriveProofFrame.json")
  deriveDoc["@context"].push(template["vocabUrl"])
  deriveDoc["credentialSubject"]["type"].push(template["templateName"])
  for(var item in revealedAttributes){
    deriveDoc["credentialSubject"][item]=revealedAttributes[item]
  }
  return deriveDoc
}



async function test() {
  var items = {
    "id":"string",
    "egg": "int",
    "test1": "normalizedString",
    "test2": "dateTime",
    "age": "int",
    "apple": "int",
    "daf": "decimal"
  }
  var attributes = {
    "id": "did:example:2378465",
    "egg": "50",
    "test1": "aksd",
    "test2": "2029-12-03T12:19:52",
    "age": "23",
    "apple": "99",
    "daf": "12.3"
  }

  issuerId = "did:example:489398593"
  const publicKeyId = issuerId + '#' + '666'
  const templateName = "testName"
  var template = await createTemplate(items, issuerId, publicKeyId, templateName)


  var inputDocument = createInputDoc(template, attributes)
  var extractResult = getVocabFromTemplate(template)



  const customDocLoader = (url) => {
    const context = template.documents[url];

    if (context) {
      return {
        contextUrl: null,
        document: context,
        documentUrl: url,
      };
    }


    throw new Error(
      `Attempted to remote load context : '${url}', please cache instead`
    );
  }
  const documentLoader = extendContextLoader(customDocLoader)

  const keyPair = await new Bls12381G2KeyPair(template.documents[template.publicKeyId]);

  //Sign the input document
  const signedDocument = await sign(inputDocument, {
    suite: new BbsBlsSignature2020({ key: keyPair }),
    purpose: new purposes.AssertionProofPurpose(),
    documentLoader,
  });

  // let verified = await verify(signedDocument, {
  //   suite: new BbsBlsSignature2020(),
  //   purpose: new purposes.AssertionProofPurpose(),
  //   documentLoader,
  // });




  // 选择性披露
  const revealAttributes = {
    "id": attributes.id,  // 通常需要保留id
    "test1": attributes.test1,
    "age": "range-18-60",
    "egg": "range-40-60",
    // "apple": "range-80-100",
  };
  var revealDocument=createRevealDoc(template,revealAttributes)

    // 生成选择性披露证明
    const derivedProof = await deriveProof(signedDocument, revealDocument, {
      suite: new BbsBlsSignatureProof2020(),
      documentLoader,
    });
  

  
    
    // 验证选择性披露的证明
    verified = await verify(derivedProof, {
      suite: new BbsBlsSignatureProof2020(),
      purpose: new purposes.AssertionProofPurpose(),
      documentLoader,
    });
  

}

test();