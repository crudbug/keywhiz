/*
 * Copyright (C) 2015 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package keywhiz.service.daos;

import com.google.common.collect.ImmutableMap;
import java.time.OffsetDateTime;
import javax.inject.Inject;
import keywhiz.KeywhizTestRunner;
import keywhiz.api.ApiDate;
import keywhiz.api.model.SecretContent;
import keywhiz.service.daos.SecretContentDAO.SecretContentDAOFactory;
import org.jooq.DSLContext;
import org.jooq.tools.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static keywhiz.jooq.tables.Secrets.SECRETS;
import static keywhiz.jooq.tables.SecretsContent.SECRETS_CONTENT;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(KeywhizTestRunner.class)
public class SecretContentDAOTest {
  @Inject DSLContext jooqContext;
  @Inject SecretContentDAOFactory secretContentDAOFactory;

  final static ApiDate date = ApiDate.now();
  ImmutableMap<String, String> metadata = ImmutableMap.of("foo", "bar");

  SecretContent secretContent1 = SecretContent.of(11, 22, "[crypted]", date, "creator", date,
      "creator", metadata, 1136214245);

  SecretContentDAO secretContentDAO;

  @Before
  public void setUp() throws Exception {
    secretContentDAO = secretContentDAOFactory.readwrite();
    long now = OffsetDateTime.now().toEpochSecond();

    jooqContext.insertInto(SECRETS, SECRETS.ID, SECRETS.NAME, SECRETS.CREATEDAT, SECRETS.UPDATEDAT)
        .values(secretContent1.secretSeriesId(), "secretName", now, now)
        .execute();

    jooqContext.insertInto(SECRETS_CONTENT)
        .set(SECRETS_CONTENT.ID, secretContent1.id())
        .set(SECRETS_CONTENT.SECRETID, secretContent1.secretSeriesId())
        .set(SECRETS_CONTENT.ENCRYPTED_CONTENT, secretContent1.encryptedContent())
        .set(SECRETS_CONTENT.CREATEDAT, secretContent1.createdAt().toEpochSecond())
        .set(SECRETS_CONTENT.CREATEDBY, secretContent1.createdBy())
        .set(SECRETS_CONTENT.UPDATEDAT, secretContent1.updatedAt().toEpochSecond())
        .set(SECRETS_CONTENT.UPDATEDBY, secretContent1.updatedBy())
        .set(SECRETS_CONTENT.METADATA, JSONObject.toJSONString(secretContent1.metadata()))
        .set(SECRETS_CONTENT.EXPIRY, 1136214245L)
        .execute();
  }

  @Test public void createSecretContent() {
    int before = tableSize();
    secretContentDAO.createSecretContent(secretContent1.secretSeriesId()+1, "encrypted", "creator",
        metadata, 1136214245);
    assertThat(tableSize()).isEqualTo(before + 1);
  }

  @Test public void pruneOldContents() throws Exception {
    int before = tableSize();

    long id0 = secretContentDAO.createSecretContent(
        secretContent1.secretSeriesId(), "encrypted0", "creator", metadata, 1136214245);
    long id1 = secretContentDAO.createSecretContent(
        secretContent1.secretSeriesId(), "encrypted1", "creator", metadata, 1136214245);
    long id2 = secretContentDAO.createSecretContent(
        secretContent1.secretSeriesId(), "encrypted2", "creator", metadata, 1136214245);

    assertThat(tableSize()).isEqualTo(before + 3);

    // Update created_at to always be in the past
    jooqContext.update(SECRETS_CONTENT)
        .set(SECRETS_CONTENT.CREATEDAT, 0L)
        .execute();

    // Make id1 be the current version for the secret series and prune
    jooqContext.update(SECRETS)
        .set(SECRETS.CURRENT, id1)
        .where(SECRETS.ID.eq(secretContent1.secretSeriesId()))
        .execute();

    secretContentDAO.pruneOldContents(secretContent1.secretSeriesId());

    // Should have deleted id0/id2, with id1 still intact
    assertThat(secretContentDAO.getSecretContentById(id0).isPresent()).isFalse();
    assertThat(secretContentDAO.getSecretContentById(id2).isPresent()).isFalse();
    secretContentDAO.getSecretContentById(id1).get().encryptedContent().equals("encrypted1");
  }

  @Test public void getSecretContentById() {
    assertThat(secretContentDAO.getSecretContentById(secretContent1.id())).contains(secretContent1);
  }

  private int tableSize() {
    return jooqContext.fetchCount(SECRETS_CONTENT);
  }
}
